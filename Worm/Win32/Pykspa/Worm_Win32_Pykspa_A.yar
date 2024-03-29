
rule Worm_Win32_Pykspa_A{
	meta:
		description = "Worm:Win32/Pykspa.A,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0b 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 6b 79 70 65 43 6f 6e 74 72 6f 6c 41 50 49 44 69 73 63 6f 76 65 72 } //01 00  SkypeControlAPIDiscover
		$a_01_1 = {53 6b 79 70 65 43 6f 6e 74 72 6f 6c 41 50 49 41 74 74 61 63 68 } //01 00  SkypeControlAPIAttach
		$a_00_2 = {64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 } //01 00  drivers\etc\hosts
		$a_01_3 = {68 6f 73 74 73 00 00 00 5c 65 74 63 5c 00 00 00 64 72 69 76 65 72 73 } //01 00 
		$a_01_4 = {74 72 61 6e 73 66 65 72 2d 65 6e 63 6f 64 69 6e 67 } //01 00  transfer-encoding
		$a_01_5 = {25 64 2e 25 64 2e 25 64 2e 25 64 20 64 6f 77 6e 6c 6f 61 64 25 64 2e 61 76 61 73 74 2e 63 6f 6d } //01 00  %d.%d.%d.%d download%d.avast.com
		$a_01_6 = {25 64 2e 25 64 2e 25 64 2e 25 64 20 75 25 64 2e 65 73 65 74 2e 63 6f 6d } //01 00  %d.%d.%d.%d u%d.eset.com
		$a_01_7 = {53 6f 66 74 77 61 72 65 5c 52 4d 58 5c } //01 00  Software\RMX\
		$a_01_8 = {55 75 69 64 43 72 65 61 74 65 } //01 00  UuidCreate
		$a_01_9 = {53 45 54 20 55 53 45 52 53 54 41 54 55 53 20 44 4e 44 } //01 00  SET USERSTATUS DND
		$a_01_10 = {53 45 41 52 43 48 20 46 52 49 45 4e 44 53 } //00 00  SEARCH FRIENDS
	condition:
		any of ($a_*)
 
}