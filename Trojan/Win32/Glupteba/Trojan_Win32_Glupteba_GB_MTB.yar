
rule Trojan_Win32_Glupteba_GB_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {33 c1 29 45 90 01 01 89 75 90 01 01 81 f3 07 eb dd 13 81 6d 30 90 01 04 b8 41 e5 64 03 81 6d 30 90 01 04 81 45 30 90 01 04 8b 55 90 01 01 8b 4d 90 01 01 8b c2 d3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}