USE RetroGameDB;

-- ─── Company ──────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS Company
(
    CompanyID   INT          NOT NULL AUTO_INCREMENT,
    CompanyName VARCHAR(255) NOT NULL,
    YearFounded INT          NOT NULL,
    Location    VARCHAR(255) NOT NULL,
    PRIMARY KEY (CompanyID)
);

-- ─── Console ──────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS Console
(
    ConsoleID      INT          NOT NULL AUTO_INCREMENT,
    Name           VARCHAR(255) NOT NULL,
    ManufacturerID INT          NOT NULL,
    ReleaseYear    INT          NOT NULL,
    Region         VARCHAR(100) NOT NULL,
    PRIMARY KEY (ConsoleID),
    FOREIGN KEY (ManufacturerID) REFERENCES Company (CompanyID)
);

-- ─── User ─────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS User
(
    UserID   INT          NOT NULL AUTO_INCREMENT,
    Username VARCHAR(255) NOT NULL UNIQUE,
    Email    VARCHAR(255) NOT NULL,
    FullName VARCHAR(255),
    Address VARCHAR(255) NOT NULL,
    Password VARCHAR(255),
    PRIMARY KEY (UserID)
);

-- ─── Games ────────────────────────────────────────────────────────────────────
-- Platform VARCHAR replaced with ConsoleID FK
CREATE TABLE IF NOT EXISTS Games
(
    GameID      INT          NOT NULL AUTO_INCREMENT,
    Title       VARCHAR(255) NOT NULL,
    ConsoleID   INT          NOT NULL,
    `Year`      INT,
    `Condition` VARCHAR(100),
    MadeBy      INT          NOT NULL,
    OwnerID     INT          NOT NULL,
    PRIMARY KEY (GameID),
    FOREIGN KEY (ConsoleID) REFERENCES Console (ConsoleID),
    FOREIGN KEY (MadeBy) REFERENCES Company (CompanyID),
    FOREIGN KEY (OwnerID) REFERENCES User (UserID) ON DELETE CASCADE
);

-- ─── TradeOffer ───────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS TradeOffer
(
    OfferID         INT         NOT NULL AUTO_INCREMENT,
    CreatedByUserID INT         NOT NULL,
    TargetGameID    INT         NOT NULL,
    OfferedGameID   INT         NOT NULL,
    Status          VARCHAR(50) NOT NULL DEFAULT 'pending',
    CreatedAt       DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UpdatedAt       DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (OfferID),
    FOREIGN KEY (CreatedByUserID) REFERENCES User (UserID) ON DELETE CASCADE,
    FOREIGN KEY (TargetGameID) REFERENCES Games (GameID) ON DELETE CASCADE,
    FOREIGN KEY (OfferedGameID) REFERENCES Games (GameID) ON DELETE CASCADE
);

-- ─── Seed: Companies ──────────────────────────────────────────────────────────
INSERT IGNORE INTO Company (CompanyID, CompanyName, YearFounded, Location)
VALUES (1, 'Nintendo', 1889, 'Kyoto, Japan'),
       (2, 'Sega', 1945, 'Tokyo, Japan'),
       (3, 'Atari', 1972, 'Sunnyvale, CA'),
       (4, 'Capcom', 1979, 'Osaka, Japan'),
       (5, 'Konami', 1969, 'Osaka, Japan'),
       (6, 'Sony', 1946, 'Tokyo, Japan'),
       (7, 'Microsoft', 1975, 'Redmond, WA');

-- ─── Seed: Consoles ───────────────────────────────────────────────────────────
INSERT IGNORE INTO Console (ConsoleID, Name, ManufacturerID, ReleaseYear, Region)
VALUES (1, 'NES', 1, 1983, 'Japan'),
       (2, 'SNES', 1, 1990, 'Japan'),
       (3, 'Nintendo 64', 1, 1996, 'Japan'),
       (4, 'Game Boy', 1, 1989, 'Japan'),
       (5, 'Game Boy Advance', 1, 2001, 'Japan'),
       (6, 'GameCube', 1, 2001, 'Japan'),
       (7, 'Sega Genesis', 2, 1988, 'North America'),
       (8, 'Sega Saturn', 2, 1994, 'Japan'),
       (9, 'Sega Dreamcast', 2, 1998, 'Japan'),
       (10, 'Atari 2600', 3, 1977, 'North America'),
       (11, 'Atari 7800', 3, 1986, 'North America'),
       (12, 'PlayStation', 6, 1994, 'Japan'),
       (13, 'PlayStation 2', 6, 2000, 'Japan'),
       (14, 'Xbox', 7, 2001, 'North America');