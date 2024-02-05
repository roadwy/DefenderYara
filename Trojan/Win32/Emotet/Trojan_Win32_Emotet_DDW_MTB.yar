
rule Trojan_Win32_Emotet_DDW_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DDW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {ff d7 85 c0 75 26 6a 08 6a 01 53 53 8d 54 24 90 01 01 52 ff d7 85 c0 75 15 6a 08 6a 01 53 53 8d 44 24 90 1b 00 50 ff d7 90 00 } //01 00 
		$a_02_1 = {85 c0 75 2e 6a 08 6a 01 53 53 8d 4c 24 90 01 01 51 ff 15 90 01 04 85 c0 75 19 6a 08 6a 01 53 53 8d 54 24 90 1b 00 52 ff 15 90 01 04 85 c0 0f 84 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}