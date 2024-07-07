
rule Trojan_Win32_Iceid_SX_MTB{
	meta:
		description = "Trojan:Win32/Iceid.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {59 50 8b c3 5a 8b ca 33 d2 f7 f1 8a 04 16 30 04 1f 43 3b 5d 10 75 } //1
		$a_03_1 = {8b 44 24 04 a8 03 75 90 01 01 8b 10 83 c0 04 8b ca 81 ea 01 01 01 01 81 e2 80 80 80 80 74 eb f7 d1 23 d1 74 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}