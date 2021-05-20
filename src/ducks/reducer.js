const initialState = {
    username: '',
    profile_pic: ''
}
const UPDATE_USER = 'UPDATE_USER'
const LOGOUT_USER = 'LOGOUT_USER' 
export function updateUser(user){
    return{
        type: UPDATE_USER,
        payload: user
    }
}
export function logout(){
    return{
        type: LOGOUT_USER,
        payload: null
    }
}
export default function reducer(state = initialState, action){
    switch(action.type){
        case UPDATE_USER:
            return {...state, username: action.payload.username, profile_pic: action.payload.profile_pic}
        case LOGOUT_USER:
            return {...state, username: action.payload, profile_pic: action.payload}
        default:
            return {...state}
    }
}