import {combineReducers, createStore} from 'redux'
import reducer from  './reducer'

const rootReducer = combineReducers({
    reducer: reducer
})


export default createStore(rootReducer)