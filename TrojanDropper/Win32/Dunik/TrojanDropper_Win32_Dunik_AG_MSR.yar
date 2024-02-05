
rule TrojanDropper_Win32_Dunik_AG_MSR{
	meta:
		description = "TrojanDropper:Win32/Dunik.AG!MSR,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 07 00 00 0a 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 67 75 73 69 74 69 20 6b 69 6a 69 63 65 5c 64 61 7a 20 77 69 6d 61 6b 61 63 6f 76 69 76 65 35 33 5c 74 6f 6c 75 6a 36 38 2d 70 2e 70 64 62 } //02 00 
		$a_80_1 = {53 6f 66 74 50 72 6f 64 } //SoftProd  02 00 
		$a_80_2 = {53 6c 61 79 65 72 50 61 74 68 } //SlayerPath  01 00 
		$a_80_3 = {4e 6f 66 69 6d 6f 64 75 70 75 63 69 73 75 63 20 6e 75 62 65 78 65 77 65 20 6c 61 74 6f 62 61 63 61 6a 69 63 75 70 69 20 78 61 73 75 6d 65 76 6f 77 61 6a 20 77 69 6a 6f 68 69 70 69 } //Nofimodupucisuc nubexewe latobacajicupi xasumevowaj wijohipi  01 00 
		$a_01_4 = {47 6c 6f 62 61 6c 52 65 41 6c 6c 6f 63 } //01 00 
		$a_01_5 = {43 6c 69 65 6e 74 54 6f 53 63 72 65 65 6e } //01 00 
		$a_01_6 = {43 72 65 61 74 65 46 69 6c 65 41 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDropper_Win32_Dunik_AG_MSR_2{
	meta:
		description = "TrojanDropper:Win32/Dunik.AG!MSR,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 0a 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 62 61 74 61 6a 61 68 75 70 75 64 6f 62 75 5c 6b 65 6d 6f 33 31 20 63 61 6d 61 6c 69 78 75 68 69 78 61 2d 68 69 66 61 70 5c 74 6f 77 6f 76 2e 70 64 62 } //01 00 
		$a_80_1 = {44 69 78 65 68 75 6e 20 6d 6f 68 75 68 75 74 6f 73 65 7a 61 73 61 66 20 79 65 6c 61 64 75 79 6f 72 6f 77 69 6c 20 67 65 70 65 64 6f 78 61 73 69 6c 65 74 65 4c 4b 61 64 69 70 } //Dixehun mohuhutosezasaf yeladuyorowil gepedoxasileteLKadip  01 00 
		$a_80_2 = {4e 6f 66 69 6d 6f 64 75 70 75 63 69 73 75 63 20 6e 75 62 65 78 65 77 65 20 6c 61 74 6f 62 61 63 61 6a 69 63 75 70 69 20 78 61 73 75 6d 65 76 6f 77 61 6a 20 77 69 6a 6f 68 69 70 69 } //Nofimodupucisuc nubexewe latobacajicupi xasumevowaj wijohipi  01 00 
		$a_01_3 = {48 65 61 70 52 65 41 6c 6c 6f 63 } //01 00 
		$a_01_4 = {43 6c 69 65 6e 74 54 6f 53 63 72 65 65 6e } //01 00 
		$a_01_5 = {43 72 65 61 74 65 46 69 6c 65 41 } //00 00 
	condition:
		any of ($a_*)
 
}