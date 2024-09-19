
rule Trojan_BAT_LummaStealer_NA_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {72 93 00 00 70 1b 28 ?? 00 00 06 72 93 00 00 70 28 ?? 00 00 0a 13 06 11 06 28 ?? 00 00 0a 16 } //5
		$a_01_1 = {6c 6f 61 64 5f 77 6f 72 6c 64 2e 65 78 65 } //1 load_world.exe
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}
rule Trojan_BAT_LummaStealer_NA_MTB_2{
	meta:
		description = "Trojan:BAT/LummaStealer.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {28 61 38 00 06 0c 28 ?? ?? 00 0a 03 6f ?? ?? 00 0a 28 ?? ?? 00 06 0d 73 ?? ?? 00 0a 13 04 28 ?? ?? 00 06 13 05 11 05 08 6f ?? ?? 00 0a 11 05 09 6f ?? ?? 00 0a 11 04 11 05 } //5
		$a_01_1 = {6c 69 76 65 5f 73 74 72 65 61 6d 5f 66 72 6f 6d 5f 63 6f 73 6d 6f 73 5f 65 76 65 6e 74 73 5f 61 70 70 2e 65 78 65 } //1 live_stream_from_cosmos_events_app.exe
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}
rule Trojan_BAT_LummaStealer_NA_MTB_3{
	meta:
		description = "Trojan:BAT/LummaStealer.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 07 00 00 "
		
	strings :
		$a_03_0 = {02 03 02 4b 03 04 61 05 61 58 0e 07 0e 04 e0 95 58 7e ?? ?? 00 04 0e 06 17 59 e0 95 58 0e 05 } //5
		$a_81_1 = {41 63 63 6f 75 6e 74 2f 4c 6f 67 69 6e } //1 Account/Login
		$a_81_2 = {57 65 62 4d 61 74 72 69 78 2e 57 65 62 44 61 74 61 2e 52 65 73 6f 75 72 63 65 73 2e 57 65 62 44 61 74 61 52 65 73 6f 75 72 63 65 73 } //1 WebMatrix.WebData.Resources.WebDataResources
		$a_81_3 = {65 6e 61 62 6c 65 50 61 73 73 77 6f 72 64 52 65 73 65 74 } //1 enablePasswordReset
		$a_81_4 = {5b 50 61 73 73 77 6f 72 64 5d 2c 20 50 61 73 73 77 6f 72 64 53 61 6c 74 } //1 [Password], PasswordSalt
		$a_81_5 = {53 45 54 20 50 61 73 73 77 6f 72 64 46 61 69 6c 75 72 65 73 53 69 6e 63 65 4c 61 73 74 53 75 63 63 65 73 73 } //1 SET PasswordFailuresSinceLastSuccess
		$a_81_6 = {63 72 79 70 74 6f 4b 65 79 20 3d } //1 cryptoKey =
	condition:
		((#a_03_0  & 1)*5+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=11
 
}