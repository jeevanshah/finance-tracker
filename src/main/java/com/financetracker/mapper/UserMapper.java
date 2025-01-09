package com.financetracker.mapper;

import com.financetracker.dto.UserDTO;
import com.financetracker.entity.User;
import org.mapstruct.Mapper;

import java.util.List;
import java.util.Optional;

@Mapper(componentModel = "spring")
public interface UserMapper {

    default Optional<User> mapToOptional(User user){
        return Optional.ofNullable(user);
    }

    default User optionalToEntity(Optional<User> userOptional) {
        return userOptional.orElse(null);
    }
    UserDTO toDto(User user);
    User toEntity(UserDTO userDTO);

    List<UserDTO> toDtoList(List<User> users);
    List<User> toEntityList(List<UserDTO> userDTOS);

}
