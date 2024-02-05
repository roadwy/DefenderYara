
rule Trojan_Win32_Glupteba_RA_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_02_0 = {8b f7 c1 ee 05 03 85 90 01 04 03 b5 90 01 04 89 45 90 01 01 8b 85 90 01 04 31 45 90 01 01 33 db 81 3d 90 01 04 3f 0b 00 00 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}