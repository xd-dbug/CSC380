

USE RetroGameDB;

-- ─── Company ──────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS Company (
                                       CompanyID    INT          NOT NULL AUTO_INCREMENT,
                                       CompanyName  VARCHAR(255) NOT NULL,
    YearFounded  INT          NOT NULL,
    Location     VARCHAR(255) NOT NULL,
    PRIMARY KEY (CompanyID)
    );

-- ─── User ─────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS User (
                                    UserID   INT          NOT NULL AUTO_INCREMENT,
                                    Username VARCHAR(255) NOT NULL UNIQUE,
    Email    VARCHAR(255) NOT NULL,
    FullName VARCHAR(255),
    Password VARCHAR(255),           -- bcrypt hash; NULL allowed for legacy rows
    PRIMARY KEY (UserID)
    );

-- ─── Games ────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS Games (
                                     GameID    INT          NOT NULL AUTO_INCREMENT,
                                     Title     VARCHAR(255) NOT NULL,
    Platform  VARCHAR(255) NOT NULL,
    `Year`    INT,
    `Condition` VARCHAR(100),
    MadeBy    INT          NOT NULL,
    OwnerID   INT          NOT NULL,
    PRIMARY KEY (GameID),
    FOREIGN KEY (MadeBy)   REFERENCES Company(CompanyID),
    FOREIGN KEY (OwnerID)  REFERENCES User(UserID) ON DELETE CASCADE
    );

-- ─── TradeOffer ───────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS TradeOffer (
                                          OfferID          INT         NOT NULL AUTO_INCREMENT,
                                          CreatedByUserID  INT         NOT NULL,
                                          TargetGameID     INT         NOT NULL,
                                          OfferedGameID    INT         NOT NULL,
                                          Status           VARCHAR(50) NOT NULL DEFAULT 'pending',
    CreatedAt        DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UpdatedAt        DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (OfferID),
    FOREIGN KEY (CreatedByUserID) REFERENCES User(UserID)  ON DELETE CASCADE,
    FOREIGN KEY (TargetGameID)    REFERENCES Games(GameID) ON DELETE CASCADE,
    FOREIGN KEY (OfferedGameID)   REFERENCES Games(GameID) ON DELETE CASCADE
    );

-- ─── Optional seed data (remove if you don't want it) ─────────────────────────
INSERT IGNORE INTO Company (CompanyID, CompanyName, YearFounded, Location) VALUES
    (1, 'Nintendo',  1889, 'Kyoto, Japan'),
    (2, 'Sega',      1945, 'Tokyo, Japan'),
    (3, 'Atari',     1972, 'Sunnyvale, CA'),
    (4, 'Capcom',    1979, 'Osaka, Japan'),
    (5, 'Konami',    1969, 'Osaka, Japan');