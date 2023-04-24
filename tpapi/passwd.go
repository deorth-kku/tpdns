package tpapi

const (
	secret_key         = "RDpbLfCPsJZ7fiv"
	encrypted_string   = "yLwVl0zKqws7LgKPRQ84Mdt708T1qQ3Ha7xv3H7NyU84p21BriUWBU43odz3iP4rBL3cD02KZciXTysVXiV8ngg6vL48rPJyAUw0HurW20xqxv9aYb4M9wK1Ae0wlro510qXeU07kV57fQMc8L6aLgMLwygtc0F10a0Dg70TOoouyFhdysuRMO51yY5ZlOZZLEal1h0t9YQW0Ko7oBwmCAHoic4HYbUyVeU3sfQ1xtXcPcf1aT303wAQhv66qzW"
	l_secret_key       = len(secret_key)
	l_encrypted_string = byte(len(encrypted_string))
)

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func passwdEncryption(passwd string) string {
	l_passwd := len(passwd)
	e := max(l_passwd, l_secret_key)

	result := ""
	for l := 0; l < e; l++ {
		m := byte(187)
		k := byte(187)
		if l >= l_passwd {
			m = secret_key[l]
		} else {
			if l >= l_secret_key {
				k = passwd[l]
			} else {
				k = passwd[l]
				m = secret_key[l]
			}
		}
		result += string(encrypted_string[(k^m)%l_encrypted_string])
	}
	return result
}
