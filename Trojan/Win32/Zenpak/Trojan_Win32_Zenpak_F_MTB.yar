
rule Trojan_Win32_Zenpak_F_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.F!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {0f b6 3c 06 01 d7 89 45 d4 31 d2 8b 5d f0 f7 f3 8b 75 ec 0f b6 14 16 01 d7 89 f8 99 f7 f9 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Zenpak_F_MTB_2{
	meta:
		description = "Trojan:Win32/Zenpak.F!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_01_0 = {32 00 55 00 6c 00 69 00 67 00 68 00 74 00 73 00 66 00 6f 00 75 00 72 00 74 00 68 00 75 00 54 00 71 00 73 00 65 00 65 00 64 00 57 00 } //01 00  2UlightsfourthuTqseedW
		$a_01_1 = {67 00 69 00 76 00 65 00 73 00 74 00 61 00 72 00 73 00 67 00 6f 00 64 00 75 00 6e 00 64 00 65 00 72 00 73 00 65 00 63 00 6f 00 6e 00 64 00 77 00 34 00 76 00 64 00 51 00 } //01 00  givestarsgodundersecondw4vdQ
		$a_01_2 = {65 73 65 65 64 61 70 70 65 61 72 77 68 61 6c 65 73 77 61 73 } //01 00  eseedappearwhaleswas
		$a_01_3 = {6c 00 61 00 6e 00 64 00 41 00 54 00 61 00 6c 00 73 00 6f 00 31 00 66 00 72 00 75 00 69 00 74 00 62 00 65 00 61 00 73 00 74 00 } //01 00  landATalso1fruitbeast
		$a_01_4 = {75 4e 6d 6f 76 65 74 68 47 68 65 72 62 67 61 74 68 65 72 65 64 4d 46 73 65 61 } //01 00  uNmovethGherbgatheredMFsea
		$a_01_5 = {63 00 61 00 74 00 74 00 6c 00 65 00 68 00 65 00 2e 00 6d 00 61 00 53 00 6f 00 66 00 6f 00 72 00 79 00 6f 00 75 00 2e 00 72 00 65 00 61 00 6c 00 73 00 6f 00 62 00 72 00 6f 00 75 00 67 00 68 00 74 00 5a 00 } //01 00  cattlehe.maSoforyou.realsobroughtZ
		$a_01_6 = {64 00 61 00 79 00 2c 00 63 00 72 00 65 00 65 00 70 00 65 00 74 00 68 00 64 00 69 00 76 00 69 00 64 00 65 00 2e 00 69 00 42 00 4d 00 61 00 6e 00 2e 00 77 00 69 00 6e 00 67 00 65 00 64 00 2e 00 4b 00 6c 00 69 00 6b 00 65 00 6e 00 65 00 73 00 73 00 2c 00 5a 00 } //01 00  day,creepethdivide.iBMan.winged.Klikeness,Z
		$a_01_7 = {4d 00 74 00 67 00 72 00 65 00 65 00 6e 00 35 00 6d 00 6f 00 76 00 65 00 64 00 2e 00 72 00 44 00 61 00 6c 00 6c 00 6c 00 69 00 66 00 65 00 } //01 00  Mtgreen5moved.rDalllife
		$a_01_8 = {73 65 61 73 6f 6e 73 2e 38 73 69 78 74 68 50 55 53 73 30 } //01 00  seasons.8sixthPUSs0
		$a_01_9 = {79 6f 75 2e 6c 6c 45 69 46 6f 72 74 68 2e 76 65 72 79 47 } //00 00  you.llEiForth.veryG
	condition:
		any of ($a_*)
 
}