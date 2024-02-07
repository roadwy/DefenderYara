
rule Trojan_BAT_Bsymem_NEAA_MTB{
	meta:
		description = "Trojan:BAT/Bsymem.NEAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 05 00 00 05 00 "
		
	strings :
		$a_01_0 = {32 45 39 31 37 42 41 30 2d 44 35 45 43 2d 34 45 46 37 2d 38 31 46 31 2d 36 43 37 45 35 32 42 43 41 46 41 31 } //05 00  2E917BA0-D5EC-4EF7-81F1-6C7E52BCAFA1
		$a_01_1 = {41 00 69 00 76 00 69 00 65 00 77 00 2e 00 65 00 78 00 65 00 } //02 00  Aiview.exe
		$a_01_2 = {50 6f 77 65 72 65 64 20 62 79 20 53 6d 61 72 74 41 73 73 65 6d 62 6c 79 20 38 2e 31 2e 32 2e 34 39 37 35 } //02 00  Powered by SmartAssembly 8.1.2.4975
		$a_01_3 = {53 6d 61 72 74 41 73 73 65 6d 62 6c 79 2e 48 6f 75 73 65 4f 66 43 61 72 64 73 } //01 00  SmartAssembly.HouseOfCards
		$a_01_4 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //00 00  WriteProcessMemory
	condition:
		any of ($a_*)
 
}