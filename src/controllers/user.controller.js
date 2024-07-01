import { asyncHandler } from '../utils/asyncHandler.js';
import { ApiError } from '../utils/ApiError.js';
import { User } from '../models/user.model.js';
import { uploadOnCloudinary } from "../utils/cloudinary.js";
import { ApiResponse } from '../utils/ApiResponse.js';

const generateAccessTokenAndRefreshToken = async(userId) => {

    try {
        const user = await User.findById(userId)
        const accessToken = user.generateAccessToken()
        const refreshToken = user.generateRefreshToken()

        user.refreshToken = refreshToken
        await user.save({validateBeforeSave: false})

        return {accessToken, refreshToken}
        
    } catch (error) {
        throw new ApiError(500, "Something went wrong while generating tokens")
    }
}

// Register a new user
const registerUser = asyncHandler(async (req, res) => {

     // get user details from frontend
    // validation - not empty
    // check if user already exists: username, email
    // check for images, check for avatar
    // upload them to cloudinary, avatar
    // create user object - create entry in db
    // remove password and refresh token field from response
    // check for user creation
    // return res

    // Destructure user details from the request body
    const { fullName, email, username, password } = req.body;

    // Validate that none of the fields are empty
    if (
        [fullName, email, username, password].some((field) => field?.trim() === "")
    ) {
        throw new ApiError(400, "All fields are required");
    }

    // Check if a user with the given email or username already exists
    const existedUser = await User.findOne({
        $or: [{ username }, { email }]
    });

    if (existedUser) {
        throw new ApiError(409, "User with email or username already exists");
    }

    console.log(req.files);

    // Get the local path of the avatar file from the request
    const avatarLocalPath = req.files?.avatar[0]?.path;

    // Initialize cover image path if it exists in the request
    let coverImageLocalPath;
    if (req.files && Array.isArray(req.files.coverImage) && req.files.coverImage.length > 0) {
        coverImageLocalPath = req.files.coverImage[0].path;
    }

    // Ensure that the avatar file is present in the request
    if (!avatarLocalPath) {
        throw new ApiError(400, "Avatar file is required");
    }

    // Upload the avatar and cover image (if exists) to Cloudinary
    const avatar = await uploadOnCloudinary(avatarLocalPath);
    const coverImage = await uploadOnCloudinary(coverImageLocalPath);

    if (!avatar) {
        throw new ApiError(400, "Avatar file is required");
    }

    // Create a new user object and save it to the database
    const user = await User.create({
        fullName,
        avatar: avatar.url,
        coverImage: coverImage?.url || "",
        email,
        password,
        username: username.toLowerCase()
    });

    // Retrieve the created user without the password and refreshToken fields
    const createdUser = await User.findById(user._id).select(
        "-password -refreshToken"
    );

    if (!createdUser) {
        throw new ApiError(500, "Something went wrong while registering the user");
    }

    // Return a success response with the created user
    return res.status(201).json(
        new ApiResponse(200, createdUser, "User registered Successfully")
    );

});

const loginUser = asyncHandler(async (req, res) => {
    // get user details from frontend
    // validation - not empty
    // check if user exists: username
    // check if password is correct
    // generate access token and refresh token
    // send cookkie with refresh token

    // Destructure user details from the request body
    const { username, email, password } = req.body;

    if(!username || !email){
        throw new ApiError(400, "Username or email is required")
    }

    const user = User.findOne({$or: [{username}, {email}]})

    if(!user)
        throw new ApiError(404, "User not found")

    const isPasswordValid = await user.isPasswordCorrect(password)

    if(!isPasswordValid)
        throw new ApiError(401, "Invalid password")

   const {accessToken,refreshToken} = await generateAccessTokenAndRefreshToken(user._id)

    const loggedInUser = await User.findById(user._id).select("-password -refreshToken")

    const options ={
        httpOnly : true,
        secure : true
    }

    return res
    .status(200)
    .cookie("accessToken",accessToken,options)
    .cookie("refreshToken",refreshToken,options)
    .json(
        new ApiResponse(200,{
            user: loggedInUser, accessToken , refreshToken
        },
        "User logged In Successfully"
    )
    )
})

const logoutUser = asyncHandler(async(req,res) => {

    await User.findByIdAndUpdate(
        req.user._id,
        {
            $set: {
                refreshToken: undefined
            }
        },
        {
            new: true
        }
    )

    const options = {
        httpOnly: true,
        secure: true
    }

    return res
    .status(200)
    .clearCookie("accessToken", options)
    .clearCookie("refreshToken", options)
    .json(new ApiResponse(200, {}, "User logged Out"))

})

export { registerUser , loginUser , logoutUser};
