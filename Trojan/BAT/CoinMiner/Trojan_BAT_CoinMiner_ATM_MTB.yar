
rule Trojan_BAT_CoinMiner_ATM_MTB{
	meta:
		description = "Trojan:BAT/CoinMiner.ATM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 06 00 00 05 00 "
		
	strings :
		$a_80_0 = {4b 47 69 45 56 64 54 64 42 30 72 7a 72 6e 39 70 47 7a 7a 30 6d 77 3d 3d } //KGiEVdTdB0rzrn9pGzz0mw==  05 00 
		$a_80_1 = {51 6b 6f 54 52 39 50 58 68 62 76 69 53 56 45 6d 32 63 59 78 61 51 3d 3d } //QkoTR9PXhbviSVEm2cYxaQ==  05 00 
		$a_00_2 = {2f 00 63 00 20 00 73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 20 00 2f 00 63 00 72 00 65 00 61 00 74 00 65 00 20 00 2f 00 66 00 20 00 2f 00 73 00 63 00 20 00 6f 00 6e 00 6c 00 6f 00 67 00 6f 00 6e 00 20 00 2f 00 72 00 6c 00 20 00 68 00 69 00 67 00 68 00 65 00 73 00 74 00 20 00 2f 00 74 00 6e 00 } //03 00  /c schtasks /create /f /sc onlogon /rl highest /tn
		$a_80_3 = {43 72 65 61 74 65 53 75 62 4b 65 79 } //CreateSubKey  03 00 
		$a_80_4 = {6a 72 73 6f 69 6c 73 63 6a 79 76 } //jrsoilscjyv  03 00 
		$a_80_5 = {2b 32 5a 4a 71 61 4e 37 63 43 4b 5a 4a 61 79 75 6e 61 71 6f 59 30 74 34 4a 58 65 34 53 43 76 6f 79 57 58 6b 6c 4d 32 6f 66 2f 35 67 61 50 4b 2b 47 34 52 36 78 55 39 62 70 35 35 49 74 55 39 2b } //+2ZJqaN7cCKZJayunaqoY0t4JXe4SCvoyWXklM2of/5gaPK+G4R6xU9bp55ItU9+  00 00 
	condition:
		any of ($a_*)
 
}