
rule Trojan_Win32_Emotet_DDY_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DDY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {6a 08 6a 01 53 53 8d 90 02 03 51 ff 15 90 01 04 85 c0 75 90 01 01 6a 08 6a 01 53 53 8d 90 02 03 52 ff 15 90 01 04 85 c0 0f 84 90 01 04 8b 90 02 03 8d 90 02 03 50 53 53 68 34 01 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}