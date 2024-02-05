
rule Trojan_Win32_Tibs_gen_M{
	meta:
		description = "Trojan:Win32/Tibs.gen!M,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8d 05 59 f7 fa ff 05 e7 1a 05 00 b9 15 bb 41 00 8b 19 0f c1 5d fc bb 05 3e 1f 00 } //00 00 
	condition:
		any of ($a_*)
 
}