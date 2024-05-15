
rule Trojan_BAT_Shellcode_SK_MTB{
	meta:
		description = "Trojan:BAT/Shellcode.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {00 06 07 06 07 91 20 a0 06 00 00 59 d2 9c 00 07 17 58 0b 07 06 8e 69 fe 04 13 0a 11 0a 2d e1 } //00 00 
	condition:
		any of ($a_*)
 
}