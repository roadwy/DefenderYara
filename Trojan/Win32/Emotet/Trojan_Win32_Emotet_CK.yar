
rule Trojan_Win32_Emotet_CK{
	meta:
		description = "Trojan:Win32/Emotet.CK,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {4c 51 59 75 74 6f 58 52 4a 70 51 42 49 2d 7a 79 56 65 2e 70 64 62 } //00 00  LQYutoXRJpQBI-zyVe.pdb
	condition:
		any of ($a_*)
 
}