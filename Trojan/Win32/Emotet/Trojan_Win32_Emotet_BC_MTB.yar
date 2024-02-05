
rule Trojan_Win32_Emotet_BC_MTB{
	meta:
		description = "Trojan:Win32/Emotet.BC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {0f b6 14 32 0f b6 04 08 03 c2 99 f7 fb 8b 45 90 01 01 03 d7 03 55 90 01 01 8a 14 02 8b 45 90 01 01 30 10 ff 45 90 01 01 8b 45 90 01 01 3b 45 90 01 01 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}