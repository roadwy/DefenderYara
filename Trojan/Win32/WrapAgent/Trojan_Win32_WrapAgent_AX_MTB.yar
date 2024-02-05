
rule Trojan_Win32_WrapAgent_AX_MTB{
	meta:
		description = "Trojan:Win32/WrapAgent.AX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f 1f 00 8a 44 0f 90 01 01 32 c3 2a c3 32 c7 88 04 31 41 3b ca 7c 90 01 01 5f 90 02 10 5e 5b 8b e5 5d c3 90 00 } //01 00 
		$a_03_1 = {8d 49 01 f7 e7 c1 ea 90 01 01 8d 04 92 03 c0 2b f8 8b c7 8b fa 04 90 01 01 88 44 90 01 01 ff 85 ff 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}