package operators

import (
	"slices"

	"range-scout/internal/model"
)

var registry = []model.Operator{
	{Key: "mci", Name: "MCI", ASNs: []string{"AS58224", "AS205647"}},
	{Key: "irancell", Name: "Irancell", ASNs: []string{"AS31549"}},
	{Key: "rightel", Name: "Rightel", ASNs: []string{"AS44244"}},
	{Key: "samantel", Name: "Samantel", ASNs: []string{"AS209596"}},
	{Key: "tci", Name: "TCI", ASNs: []string{"AS12880"}},
	{Key: "tic", Name: "TIC", ASNs: []string{"AS48147"}},
	{Key: "asiatech", Name: "Asiatech", ASNs: []string{"AS43754"}},
	{Key: "respina", Name: "Respina", ASNs: []string{"AS42337", "AS200612"}},
	{Key: "shatel", Name: "Shatel", ASNs: []string{"AS50810"}},
	{Key: "parsonline", Name: "ParsOnline", ASNs: []string{"AS24631"}},
	{Key: "mobinnet", Name: "Mobinnet", ASNs: []string{"AS48159"}},
	{Key: "fanap", Name: "Fanap", ASNs: []string{"AS49100"}},
	{Key: "sabanet", Name: "Sabanet", ASNs: []string{"AS57218"}},
	{Key: "zitel", Name: "Zitel", ASNs: []string{"AS61173"}},
	{Key: "hiweb", Name: "HiWeb", ASNs: []string{"AS61139"}},
	{Key: "toseeresaneh", Name: "ToseeResaneh", ASNs: []string{"AS48434"}},
	{Key: "afranet", Name: "Afranet", ASNs: []string{"AS29049"}},
	{Key: "ariashatel", Name: "AriaShatel", ASNs: []string{"AS25184"}},
	{Key: "nedagostar", Name: "NedaGostar", ASNs: []string{"AS39408"}},
	{Key: "farabord", Name: "Farabord", ASNs: []string{"AS197207"}},
}

func All() []model.Operator {
	out := slices.Clone(registry)
	return out
}

func ByKey(key string) (model.Operator, bool) {
	for _, op := range registry {
		if op.Key == key {
			return op, true
		}
	}

	return model.Operator{}, false
}
