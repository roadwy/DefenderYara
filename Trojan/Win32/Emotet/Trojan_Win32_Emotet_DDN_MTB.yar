
rule Trojan_Win32_Emotet_DDN_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DDN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8a d0 f6 d2 f6 d3 0a da 8a 54 24 90 01 01 0a d0 8b 44 24 90 01 01 22 da 88 1c 01 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}