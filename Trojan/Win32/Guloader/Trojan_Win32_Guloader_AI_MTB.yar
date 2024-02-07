
rule Trojan_Win32_Guloader_AI_MTB{
	meta:
		description = "Trojan:Win32/Guloader.AI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {4f 76 65 72 62 65 6c 61 73 74 65 5c 54 68 65 61 74 72 69 63 61 6c 73 2e 64 6c 6c } //01 00  Overbelaste\Theatricals.dll
		$a_01_1 = {68 65 72 69 61 70 68 6f 72 2e 69 6e 69 } //01 00  heriaphor.ini
		$a_01_2 = {6d 61 6e 79 70 6c 69 65 73 5c 54 65 72 72 6f 72 67 72 75 70 70 65 72 6e 65 73 5c 42 65 72 76 65 6c 73 65 5c 48 79 70 6e 6f 74 69 63 61 6c 6c 79 5c 55 64 73 70 61 72 69 6e 67 73 2e 55 6e 68 } //01 00  manyplies\Terrorgruppernes\Bervelse\Hypnotically\Udsparings.Unh
		$a_01_3 = {42 6c 75 65 62 61 63 6b 5c 64 69 70 68 74 68 65 72 69 61 70 68 6f 72 2e 69 6e 69 } //01 00  Blueback\diphtheriaphor.ini
		$a_01_4 = {4d 61 61 6c 65 66 6f 72 73 74 72 6b 65 72 65 37 30 5c 44 65 73 63 72 69 62 61 62 6c 65 2e 55 6e 73 } //00 00  Maaleforstrkere70\Describable.Uns
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Guloader_AI_MTB_2{
	meta:
		description = "Trojan:Win32/Guloader.AI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 0f 00 00 01 00 "
		
	strings :
		$a_01_0 = {42 00 61 00 61 00 6b 00 65 00 72 00 73 00 72 00 69 00 6e 00 64 00 75 00 34 00 } //01 00  Baakersrindu4
		$a_01_1 = {4e 00 6f 00 74 00 61 00 72 00 69 00 7a 00 61 00 35 00 } //01 00  Notariza5
		$a_01_2 = {53 00 69 00 6b 00 6b 00 65 00 72 00 68 00 65 00 34 00 } //01 00  Sikkerhe4
		$a_01_3 = {4d 00 61 00 6e 00 61 00 67 00 65 00 39 00 } //01 00  Manage9
		$a_01_4 = {4d 00 6f 00 6e 00 74 00 65 00 62 00 72 00 61 00 73 00 69 00 34 00 } //01 00  Montebrasi4
		$a_01_5 = {48 00 6a 00 70 00 61 00 73 00 74 00 65 00 75 00 72 00 69 00 73 00 } //01 00  Hjpasteuris
		$a_01_6 = {54 00 6f 00 6e 00 69 00 6e 00 67 00 65 00 } //01 00  Toninge
		$a_01_7 = {53 00 41 00 53 00 53 00 4f 00 4c 00 } //01 00  SASSOL
		$a_01_8 = {50 00 61 00 72 00 61 00 64 00 69 00 64 00 64 00 6c 00 37 00 } //01 00  Paradiddl7
		$a_01_9 = {6f 00 76 00 65 00 72 00 62 00 65 00 76 00 6f 00 } //01 00  overbevo
		$a_01_10 = {6f 00 75 00 74 00 74 00 72 00 61 00 64 00 69 00 6e 00 67 00 73 00 } //01 00  outtradings
		$a_01_11 = {73 00 74 00 65 00 74 00 69 00 73 00 65 00 72 00 65 00 74 00 68 00 61 00 } //01 00  stetiseretha
		$a_01_12 = {73 00 6b 00 69 00 66 00 74 00 69 00 6e 00 67 00 65 00 72 00 73 00 } //01 00  skiftingers
		$a_01_13 = {54 00 65 00 61 00 73 00 65 00 6c 00 65 00 72 00 73 00 } //01 00  Teaselers
		$a_00_14 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } //00 00  MSVBVM60.DLL
	condition:
		any of ($a_*)
 
}