
rule Trojan_Win32_Verfst_A{
	meta:
		description = "Trojan:Win32/Verfst.A,SIGNATURE_TYPE_PEHSTR,02 00 02 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 65 6c 6c 6f 21 21 20 54 68 69 73 20 45 78 65 63 75 74 69 76 65 20 66 69 6c 65 20 68 61 73 20 62 65 65 6e 20 69 6e 66 65 63 74 65 64 21 21 } //01 00  Hello!! This Executive file has been infected!!
		$a_01_1 = {3a 6e 74 6f 73 74 } //01 00  :ntost
		$a_01_2 = {4d 79 20 66 69 72 73 74 20 50 45 20 76 69 72 75 73 } //01 00  My first PE virus
		$a_01_3 = {41 75 74 68 6f 72 3a 59 75 68 2d 43 68 65 6e 20 43 68 65 6e } //00 00  Author:Yuh-Chen Chen
	condition:
		any of ($a_*)
 
}