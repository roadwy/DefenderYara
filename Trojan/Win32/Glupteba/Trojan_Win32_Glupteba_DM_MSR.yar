
rule Trojan_Win32_Glupteba_DM_MSR{
	meta:
		description = "Trojan:Win32/Glupteba.DM!MSR,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {d3 e8 89 45 90 01 01 8b 45 90 01 01 03 45 90 01 01 89 45 90 01 01 c7 05 90 01 04 82 cd 10 fe 8b 45 90 01 01 33 45 90 01 01 89 45 90 01 01 81 3d 90 01 04 91 05 00 00 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}