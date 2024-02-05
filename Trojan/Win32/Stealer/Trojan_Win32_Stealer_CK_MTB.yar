
rule Trojan_Win32_Stealer_CK_MTB{
	meta:
		description = "Trojan:Win32/Stealer.CK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {81 fe 55 e6 0c 09 7f 09 46 81 fe 22 be 7c 70 7c d5 } //02 00 
		$a_03_1 = {81 ff 16 76 00 00 75 05 e8 90 02 04 47 81 ff e9 66 24 00 7c ea 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}