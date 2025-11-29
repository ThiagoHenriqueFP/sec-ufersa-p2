package common;

import java.io.Serializable;

public record Request(
        Object body,
        TypeOfRequest type
) implements Serializable {
}
