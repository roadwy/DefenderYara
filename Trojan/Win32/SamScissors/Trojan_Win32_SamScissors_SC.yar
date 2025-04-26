
rule Trojan_Win32_SamScissors_SC{
	meta:
		description = "Trojan:Win32/SamScissors.SC,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 08 00 00 "
		
	strings :
		$a_80_0 = {25 73 5c 25 73 5c 25 73 5c 25 73 } //%s\%s\%s\%s  1
		$a_80_1 = {25 73 2e 6f 6c 64 } //%s.old  1
		$a_80_2 = {2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 20 25 73 20 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a } //******************************** %s ******************************  1
		$a_80_3 = {48 6f 73 74 4e 61 6d 65 3a 20 25 73 5c 72 5c 6e 44 6f 6d 61 69 6e 4e 61 6d 65 3a 20 25 73 5c 72 5c 6e 4f 73 56 65 72 73 69 6f 6e 3a 20 25 64 2e 25 64 2e 25 64 5c 72 5c 6e 5c 72 5c 6e } //HostName: %s\r\nDomainName: %s\r\nOsVersion: %d.%d.%d\r\n\r\n  1
		$a_80_4 = {25 73 5c 72 5c 6e 44 6f 6d 61 69 6e 4e 61 6d 65 3a 20 25 73 5c 72 5c 6e 4f 73 56 65 72 73 69 6f 6e 3a 20 25 64 2e 25 64 2e 25 64 5c 72 5c 6e 5c 72 5c 6e } //%s\r\nDomainName: %s\r\nOsVersion: %d.%d.%d\r\n\r\n  1
		$a_80_5 = {41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 47 6f 6f 67 6c 65 5c 43 68 72 6f 6d 65 5c 55 73 65 72 20 44 61 74 61 } //AppData\Local\Google\Chrome\User Data  1
		$a_80_6 = {53 45 4c 45 43 54 20 75 72 6c 2c 20 74 69 74 6c 65 20 46 52 4f 4d 20 75 72 6c 73 20 4f 52 44 45 52 20 42 59 20 69 64 20 44 45 53 43 20 4c 49 4d 49 54 } //SELECT url, title FROM urls ORDER BY id DESC LIMIT  1
		$a_80_7 = {5c 33 43 58 44 65 73 6b 74 6f 70 41 70 70 5c 63 6f 6e 66 69 67 2e 6a 73 6f 6e } //\3CXDesktopApp\config.json  2
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*2) >=5
 
}