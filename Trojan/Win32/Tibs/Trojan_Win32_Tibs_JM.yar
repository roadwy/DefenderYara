
rule Trojan_Win32_Tibs_JM{
	meta:
		description = "Trojan:Win32/Tibs.JM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {29 d0 0f 6e c0 0f 6e 0e 0f 73 f1 20 0f eb c8 f3 0f d6 c1 0f 13 07 81 c7 } //01 00 
	condition:
		any of ($a_*)
 
}