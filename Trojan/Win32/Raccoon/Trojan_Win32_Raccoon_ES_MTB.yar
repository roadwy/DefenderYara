
rule Trojan_Win32_Raccoon_ES_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.ES!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_81_0 = {71 77 64 65 6d 75 76 65 66 73 66 6d 63 61 } //01 00  qwdemuvefsfmca
		$a_81_1 = {46 69 66 74 68 44 69 6d 65 6e 73 69 6f 6e 41 73 63 65 6e 73 69 6f 6e } //01 00  FifthDimensionAscension
		$a_81_2 = {6d 75 65 61 65 77 63 73 64 } //01 00  mueaewcsd
		$a_81_3 = {43 6f 72 65 6d 64 69 6d 65 6e 73 } //01 00  Coremdimens
		$a_81_4 = {71 61 6e 74 75 6d 73 79 6d 65 74 72 69 63 } //01 00  qantumsymetric
		$a_81_5 = {54 68 65 47 72 65 61 74 41 77 61 6b 65 6e 69 6e 67 } //01 00  TheGreatAwakening
		$a_01_6 = {54 00 49 00 50 00 4f 00 46 00 44 00 41 00 59 00 2e 00 54 00 58 00 54 00 } //01 00  TIPOFDAY.TXT
		$a_01_7 = {5a 00 65 00 74 00 61 00 20 00 44 00 65 00 62 00 75 00 67 00 67 00 65 00 72 00 } //01 00  Zeta Debugger
		$a_01_8 = {52 00 6f 00 63 00 6b 00 20 00 44 00 65 00 62 00 75 00 67 00 67 00 65 00 72 00 } //01 00  Rock Debugger
		$a_01_9 = {75 00 69 00 61 00 6f 00 64 00 6f 00 65 00 6d 00 6b 00 63 00 65 00 61 00 6d 00 66 00 69 00 77 00 65 00 66 00 73 00 } //00 00  uiaodoemkceamfiwefs
	condition:
		any of ($a_*)
 
}