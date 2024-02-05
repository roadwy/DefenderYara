
rule Trojan_Win32_Agent_AZ_MTB{
	meta:
		description = "Trojan:Win32/Agent.AZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {2f d5 f7 29 d2 8d 04 f5 90 01 04 20 c0 0f a5 d0 89 d0 0f a3 c5 f6 c7 07 83 c7 01 d0 f8 84 c3 8a 07 66 0f a3 cb f6 c6 03 ff 34 24 38 ed 84 c0 90 00 } //01 00 
		$a_02_1 = {89 f9 66 0f ba e4 0d 66 ff c6 66 d3 ee 29 d9 66 c7 44 24 90 01 01 13 58 66 81 ee 0b 7b 0f b3 fe 8d 34 75 90 01 04 8d 74 24 20 f5 83 ef 04 f5 ff 37 8f 44 24 1c f8 a8 8a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}