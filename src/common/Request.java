package common;

import java.io.Serializable;

public record Request(
        Object body,
        TypeOfRequest type,
        int origin
) implements Serializable {
}
