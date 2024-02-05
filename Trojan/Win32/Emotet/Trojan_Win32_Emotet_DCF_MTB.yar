
rule Trojan_Win32_Emotet_DCF_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DCF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {03 c2 99 f7 fb 90 02 10 ff 15 90 01 04 8a 44 24 90 01 01 8a c8 8a d3 0a d8 8b 44 24 90 01 01 f6 d2 f6 d1 0a d1 22 d3 88 10 90 02 0c 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}