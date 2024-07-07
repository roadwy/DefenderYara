
rule VirTool_BAT_CryptoDropper_MTB{
	meta:
		description = "VirTool:BAT/CryptoDropper!MTB,SIGNATURE_TYPE_PEHSTR,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6e 68 6f 73 74 2e 65 78 65 } //1 conhost.exe
		$a_01_1 = {73 65 74 5f 50 61 73 73 77 6f 72 64 } //1 set_Password
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_3 = {55 45 39 54 56 41 3d 3d } //1 UE9TVA==
		$a_01_4 = {62 6d 56 30 49 48 4e 30 59 58 4a 30 49 47 4e 7a 63 6e 4e 7a } //1 bmV0IHN0YXJ0IGNzcnNz
		$a_01_5 = {61 48 52 30 63 44 6f 76 4c } //1 aHR0cDovL
		$a_01_6 = {59 6d 6c 75 } //1 Ymlu
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}
rule VirTool_BAT_CryptoDropper_MTB_2{
	meta:
		description = "VirTool:BAT/CryptoDropper!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {47 61 73 6f 4d 61 6e 2e 65 78 65 } //1 GasoMan.exe
		$a_01_1 = {44 6f 77 6e 6c 6f 61 64 73 74 72 69 6e 67 28 27 } //1 Downloadstring('
		$a_01_2 = {2e 4c 6f 61 64 28 5b 43 6f 6e 76 65 72 74 5d 3a 3a 46 72 6f 6d 62 61 73 65 36 34 53 74 72 69 6e 67 28 } //1 .Load([Convert]::Frombase64String(
		$a_01_3 = {70 6f 77 65 72 73 68 65 6c 6c 22 2c 20 2e 57 69 6e 64 6f 77 53 74 79 6c 65 20 3d 20 50 72 6f 63 65 73 73 57 69 6e 64 6f 77 53 74 79 6c 65 2e 48 69 64 64 65 6e } //1 powershell", .WindowStyle = ProcessWindowStyle.Hidden
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}