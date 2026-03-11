package main

import (
	"database/sql"
	"fmt"
)

const gameSelectCols = `
    g.GameID, g.Title, g.` + "`Year`" + `, g.` + "`Condition`" + `, g.OwnerID,
    con.ConsoleID, con.Name, con.ReleaseYear, con.Region,
    mfr.CompanyID, mfr.CompanyName, mfr.YearFounded, mfr.Location,
    pub.CompanyID, pub.CompanyName, pub.YearFounded, pub.Location`

const gameJoin = `
    FROM Games g
    JOIN Console con ON g.ConsoleID = con.ConsoleID
    JOIN Company mfr ON con.ManufacturerID = mfr.CompanyID
    JOIN Company pub ON g.MadeBy = pub.CompanyID`

func scanGame(row interface{ Scan(...any) error }) (game, error) {
	var g game
	err := row.Scan(
		&g.ID, &g.Title, &g.Year, &g.Condition, &g.OwnerID,
		&g.Console.ID, &g.Console.Name, &g.Console.ReleaseYear, &g.Console.Region,
		&g.Console.Manufacturer.ID, &g.Console.Manufacturer.CompanyName,
		&g.Console.Manufacturer.YearFounded, &g.Console.Manufacturer.Location,
		&g.MadeBy.ID, &g.MadeBy.CompanyName, &g.MadeBy.YearFounded, &g.MadeBy.Location,
	)
	return g, err
}

const consoleSelectCols = `
    con.ConsoleID, con.Name, con.ReleaseYear, con.Region,
    mfr.CompanyID, mfr.CompanyName, mfr.YearFounded, mfr.Location`

const consoleJoin = `
    FROM Console con
    JOIN Company mfr ON con.ManufacturerID = mfr.CompanyID`

func scanConsole(row interface{ Scan(...any) error }) (console, error) {
	var c console
	err := row.Scan(
		&c.ID, &c.Name, &c.ReleaseYear, &c.Region,
		&c.Manufacturer.ID, &c.Manufacturer.CompanyName,
		&c.Manufacturer.YearFounded, &c.Manufacturer.Location,
	)
	return c, err
}

func scanEmbeddedGame(g *game, row *sql.Rows) error {
	return row.Scan(
		&g.ID, &g.Title, &g.Year, &g.Condition, &g.OwnerID,
		&g.Console.ID, &g.Console.Name, &g.Console.ReleaseYear, &g.Console.Region,
		&g.Console.Manufacturer.ID, &g.Console.Manufacturer.CompanyName,
		&g.Console.Manufacturer.YearFounded, &g.Console.Manufacturer.Location,
		&g.MadeBy.ID, &g.MadeBy.CompanyName, &g.MadeBy.YearFounded, &g.MadeBy.Location,
	)
}

func gameOfferCols(alias, conAlias, mfrAlias, pubAlias string) string {
	return fmt.Sprintf(`
    %s.GameID, %s.Title, %s.`+"`Year`"+`, %s.`+"`Condition`"+`, %s.OwnerID,
    %s.ConsoleID, %s.Name, %s.ReleaseYear, %s.Region,
    %s.CompanyID, %s.CompanyName, %s.YearFounded, %s.Location,
    %s.CompanyID, %s.CompanyName, %s.YearFounded, %s.Location`,
		// game columns (5)
		alias, alias, alias, alias, alias,
		// console columns (4)
		conAlias, conAlias, conAlias, conAlias,
		// manufacturer columns (4)
		mfrAlias, mfrAlias, mfrAlias, mfrAlias,
		// publisher columns (4)
		pubAlias, pubAlias, pubAlias, pubAlias,
	)
}

func scanTradeOfferRows(rows *sql.Rows) ([]tradeOfferResponse, error) {
	var offers []tradeOfferResponse

	for rows.Next() {
		var offer tradeOfferResponse
		var createdAt, updatedAt string

		err := rows.Scan(
			// trade offer fields (7)
			&offer.ID, &offer.CreatedByUserID, &offer.TargetGameID,
			&offer.OfferedGameID, &offer.Status, &createdAt, &updatedAt,
			// creator user fields (4)
			&offer.CreatedByUser.ID, &offer.CreatedByUser.Username,
			&offer.CreatedByUser.Email, &offer.CreatedByUser.FullName,
			// target game: GameID, Title, Year, Condition, OwnerID (5)
			&offer.TargetGame.ID, &offer.TargetGame.Title,
			&offer.TargetGame.Year, &offer.TargetGame.Condition, &offer.TargetGame.OwnerID,
			// target game console (4)
			&offer.TargetGame.Console.ID, &offer.TargetGame.Console.Name,
			&offer.TargetGame.Console.ReleaseYear, &offer.TargetGame.Console.Region,
			// target game console manufacturer (4)
			&offer.TargetGame.Console.Manufacturer.ID, &offer.TargetGame.Console.Manufacturer.CompanyName,
			&offer.TargetGame.Console.Manufacturer.YearFounded, &offer.TargetGame.Console.Manufacturer.Location,
			// target game publisher (4)
			&offer.TargetGame.MadeBy.ID, &offer.TargetGame.MadeBy.CompanyName,
			&offer.TargetGame.MadeBy.YearFounded, &offer.TargetGame.MadeBy.Location,
			// offered game: GameID, Title, Year, Condition, OwnerID (5)
			&offer.OfferedGame.ID, &offer.OfferedGame.Title,
			&offer.OfferedGame.Year, &offer.OfferedGame.Condition, &offer.OfferedGame.OwnerID,
			// offered game console (4)
			&offer.OfferedGame.Console.ID, &offer.OfferedGame.Console.Name,
			&offer.OfferedGame.Console.ReleaseYear, &offer.OfferedGame.Console.Region,
			// offered game console manufacturer (4)
			&offer.OfferedGame.Console.Manufacturer.ID, &offer.OfferedGame.Console.Manufacturer.CompanyName,
			&offer.OfferedGame.Console.Manufacturer.YearFounded, &offer.OfferedGame.Console.Manufacturer.Location,
			// offered game publisher (4)
			&offer.OfferedGame.MadeBy.ID, &offer.OfferedGame.MadeBy.CompanyName,
			&offer.OfferedGame.MadeBy.YearFounded, &offer.OfferedGame.MadeBy.Location,
		)
		if err != nil {
			return nil, err
		}

		offer.CreatedAt = createdAt
		offer.UpdatedAt = updatedAt
		offers = append(offers, offer)
	}

	if offers == nil {
		offers = []tradeOfferResponse{}
	}
	return offers, nil
}
