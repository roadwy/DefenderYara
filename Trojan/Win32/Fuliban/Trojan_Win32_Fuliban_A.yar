
rule Trojan_Win32_Fuliban_A{
	meta:
		description = "Trojan:Win32/Fuliban.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 75 6c 69 70 61 6f 2e 63 6f 6d 2f 73 6f 75 2e 70 68 70 3f 6d 6f 62 61 6e 3d 33 } //01 00  fulipao.com/sou.php?moban=3
		$a_01_1 = {2f 66 75 6c 69 70 61 6f 5f 62 61 6e 62 65 6e 2e 70 68 70 } //01 00  /fulipao_banben.php
		$a_01_2 = {32 33 34 35 2e 63 6f 6d 2f 3f 6b 77 65 69 67 65 } //01 00  2345.com/?kweige
		$a_01_3 = {68 61 6f 31 32 33 5f 90 02 10 2e 65 78 65 00 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4d 61 69 6e 5c 53 74 61 72 74 20 50 61 67 65 } //01 00 
		$a_01_4 = {2e 6c 65 73 6f 75 77 75 67 75 6f 6a 69 65 2e 63 6f 6d 2f 6a 69 71 69 6e 67 } //00 00  .lesouwuguojie.com/jiqing
		$a_00_5 = {5d 04 00 } //00 7d 
	condition:
		any of ($a_*)
 
}