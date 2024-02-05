
rule Trojan_Win32_Glupteba_DSN_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.DSN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {bb 87 d5 7c 3a 81 45 90 01 01 8c eb 73 22 8b 45 90 01 01 8b 4d 90 01 01 8b d0 03 f0 d3 e0 c1 ea 05 03 55 90 01 01 56 03 45 90 01 01 89 55 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}