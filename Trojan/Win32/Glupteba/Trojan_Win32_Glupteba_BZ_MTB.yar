
rule Trojan_Win32_Glupteba_BZ_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.BZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {5a 21 db 49 e8 90 01 04 21 cb 29 c9 31 17 09 db 68 90 01 04 8b 0c 24 83 c4 04 81 c7 90 01 04 01 c9 39 c7 75 d3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Glupteba_BZ_MTB_2{
	meta:
		description = "Trojan:Win32/Glupteba.BZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {b8 d8 85 40 00 81 eb 90 01 04 e8 90 01 04 31 07 bb a7 16 e9 ba 47 81 e9 90 01 04 39 d7 75 de 09 cb bb 36 c6 8a dd 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}