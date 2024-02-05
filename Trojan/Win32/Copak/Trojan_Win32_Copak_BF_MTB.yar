
rule Trojan_Win32_Copak_BF_MTB{
	meta:
		description = "Trojan:Win32/Copak.BF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {5e 29 c2 e8 90 02 04 31 33 01 d0 21 c0 43 39 fb 75 e8 90 00 } //02 00 
		$a_01_1 = {31 0a bb 4b ec b2 9e 29 c3 81 c2 04 00 00 00 81 c6 82 36 3b 50 39 fa 75 e2 } //03 00 
		$a_01_2 = {59 29 fa 01 fa 46 81 ea 85 b2 a8 49 81 fe cf 71 00 01 75 b1 } //03 00 
		$a_01_3 = {41 42 5b 01 ca 09 c9 09 d1 40 49 81 f8 1b 00 00 01 75 d7 } //00 00 
	condition:
		any of ($a_*)
 
}