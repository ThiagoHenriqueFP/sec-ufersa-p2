package common;

import java.io.Serializable;

public record Response(
        Object body
) implements Serializable {
}
