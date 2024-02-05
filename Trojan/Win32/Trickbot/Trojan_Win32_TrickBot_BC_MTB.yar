
rule Trojan_Win32_TrickBot_BC_MTB{
	meta:
		description = "Trojan:Win32/TrickBot.BC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f be 04 2f 8a d3 8a c8 f6 d2 f6 d1 0a d1 0a d8 22 d3 88 17 83 c7 01 83 6c 24 90 01 01 01 0f 85 90 00 } //01 00 
		$a_02_1 = {83 c0 01 99 b9 90 01 04 f7 90 01 01 8b 4c 24 90 01 01 68 90 01 04 68 90 01 04 8b f2 0f b6 04 0e 03 c3 99 bb 90 01 04 f7 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}