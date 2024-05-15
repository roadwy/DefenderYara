
rule Trojan_Win32_Fauppod_AFU_MTB{
	meta:
		description = "Trojan:Win32/Fauppod.AFU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_01_0 = {6e 69 67 68 74 74 72 65 65 2e 77 52 67 69 76 65 6e 75 70 6f 6e 33 74 68 65 6d 6d 6f 76 65 74 68 30 } //01 00  nighttree.wRgivenupon3themmoveth0
		$a_01_1 = {46 68 4c 59 6f 75 2e 6c 6c 67 72 65 61 74 65 72 34 74 68 65 69 72 } //01 00  FhLYou.llgreater4their
		$a_01_2 = {37 6f 66 69 72 6d 61 6d 65 6e 74 6f 72 45 } //01 00  7ofirmamentorE
		$a_01_3 = {69 69 73 6e 2e 74 69 73 52 68 69 73 78 61 62 6f 76 65 66 6f 75 72 74 68 } //01 00  iisn.tisRhisxabovefourth
		$a_01_4 = {65 61 72 74 68 65 76 65 6e 69 6e 67 73 6f } //01 00  eartheveningso
		$a_01_5 = {66 6f 77 6c 31 53 67 72 65 61 74 77 61 74 65 72 73 72 6b 66 6f 75 72 74 68 } //01 00  fowl1Sgreatwatersrkfourth
		$a_01_6 = {32 6e 46 6f 5a 57 61 73 2e 69 73 } //01 00  2nFoZWas.is
		$a_01_7 = {67 61 74 68 65 72 65 64 67 72 65 61 74 48 73 65 63 6f 6e 64 50 6c 61 63 65 6d 61 6e 62 6c 69 6b 65 6e 65 73 73 43 39 } //01 00  gatheredgreatHsecondPlacemanblikenessC9
		$a_01_8 = {64 6e 69 74 6e 72 77 61 68 34 34 2e 64 6c 6c } //01 00  dnitnrwah44.dll
		$a_01_9 = {53 6a 73 74 41 66 66 64 75 72 6f } //00 00  SjstAffduro
	condition:
		any of ($a_*)
 
}