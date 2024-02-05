
rule Trojan_Win32_Remcos_AP_MTB{
	meta:
		description = "Trojan:Win32/Remcos.AP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {69 64 65 6b 6e 6f 74 00 02 4f ad 33 99 66 cf 11 b7 0c 00 aa 00 60 d3 93 48 45 4d 4f 50 45 58 49 53 6b 72 6f 70 73 } //01 00 
		$a_01_1 = {42 14 b2 90 00 6c 50 c8 b5 2c 5a 12 79 e8 49 6a 77 31 24 e8 f3 7f } //00 00 
	condition:
		any of ($a_*)
 
}