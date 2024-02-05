
rule Trojan_Win32_Glupteba_NW_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.NW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {39 db 74 01 ea 31 0f 81 c7 04 00 00 00 39 df } //01 00 
		$a_01_1 = {31 0f 81 c7 04 00 00 00 39 df 75 ef } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Glupteba_NW_MTB_2{
	meta:
		description = "Trojan:Win32/Glupteba.NW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {03 df 03 ca 33 90 02 03 33 90 02 03 89 90 02 03 89 90 02 05 8b 90 02 05 29 90 02 03 8b 90 02 05 29 90 02 03 ff 90 02 05 8b 90 02 03 0f 90 02 05 5f 89 90 02 03 89 90 02 05 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}