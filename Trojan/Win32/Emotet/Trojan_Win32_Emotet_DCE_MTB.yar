
rule Trojan_Win32_Emotet_DCE_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DCE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {01 de 21 fe 8b 7c 24 90 01 01 32 14 37 8b 74 24 90 01 01 81 c6 90 01 04 8b 7c 24 90 01 01 88 14 0f 01 f1 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}