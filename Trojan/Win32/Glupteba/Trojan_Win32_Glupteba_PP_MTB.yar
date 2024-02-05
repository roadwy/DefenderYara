
rule Trojan_Win32_Glupteba_PP_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.PP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {eb 0d 8b 85 90 02 04 40 89 85 90 02 04 81 bd 90 02 08 7d 10 83 bd 90 02 05 75 05 e8 90 02 04 eb d7 68 90 02 04 ff 35 90 02 04 ff 35 90 02 04 e8 90 02 04 e8 90 02 04 33 c0 5f 5e c9 c2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}