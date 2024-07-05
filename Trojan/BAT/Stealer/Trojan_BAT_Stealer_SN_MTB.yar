
rule Trojan_BAT_Stealer_SN_MTB{
	meta:
		description = "Trojan:BAT/Stealer.SN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {00 11 04 11 0a 02 11 0a 91 03 11 0a 03 6f 16 00 00 0a 5d 6f 17 00 00 0a 61 d2 9c 00 11 0a 17 58 13 0a 11 0a 02 8e 69 fe 04 13 0b 11 0b 3a ce ff ff ff } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Stealer_SN_MTB_2{
	meta:
		description = "Trojan:BAT/Stealer.SN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {11 0d 6f 73 00 00 06 13 17 11 0d 6f 73 00 00 06 13 18 11 04 11 17 11 18 6f 40 00 00 0a 11 16 17 58 13 16 11 16 11 0c 3f d4 ff ff ff } //02 00 
		$a_81_1 = {57 65 65 6b 65 6e 64 2e 65 78 65 } //00 00  Weekend.exe
	condition:
		any of ($a_*)
 
}