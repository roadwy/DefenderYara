
rule Trojan_Win32_Emotet_DVP_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DVP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_02_0 = {8b c7 c1 e9 05 03 0d 90 01 04 c1 e0 04 03 05 90 01 04 33 c8 8d 04 3b 33 c8 8d 9b 90 01 04 2b f1 4a 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}