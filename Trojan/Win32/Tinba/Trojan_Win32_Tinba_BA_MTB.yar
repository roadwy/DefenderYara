
rule Trojan_Win32_Tinba_BA_MTB{
	meta:
		description = "Trojan:Win32/Tinba.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {2b d0 8a 4d e4 2a ca 88 4d e4 8b 55 d0 0f af 55 f4 8b 45 dc 03 c2 89 45 } //01 00 
		$a_01_1 = {6b 66 52 48 67 70 47 6f 54 72 } //01 00  kfRHgpGoTr
		$a_01_2 = {65 4e 49 41 50 46 76 44 69 44 } //01 00  eNIAPFvDiD
		$a_01_3 = {45 59 55 4c 79 4e 6d } //01 00  EYULyNm
		$a_01_4 = {49 77 41 4e 65 69 } //00 00  IwANei
	condition:
		any of ($a_*)
 
}