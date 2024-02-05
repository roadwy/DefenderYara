
rule Trojan_Win32_Glupteba_NZ_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.NZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {30 04 16 42 3b d7 90 18 90 18 55 8b ec 51 a1 90 02 04 69 90 02 05 a3 90 02 04 c7 45 90 02 05 81 45 90 02 05 8b 90 02 05 01 90 02 05 0f 90 02 06 25 90 02 04 8b e5 5d c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}