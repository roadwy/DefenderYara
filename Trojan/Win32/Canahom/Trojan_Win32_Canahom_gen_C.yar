
rule Trojan_Win32_Canahom_gen_C{
	meta:
		description = "Trojan:Win32/Canahom.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b fe 8b ce f7 d9 81 c1 90 01 04 42 ad 8b f7 33 c2 66 3d 43 3a 75 f4 ac 32 c2 aa e2 fa c3 90 00 } //01 00 
		$a_03_1 = {66 81 7e 01 3a 5c 74 1f e8 90 01 04 8b c8 48 75 fb 83 e9 02 51 5a 8b fe 8d 0d 90 01 04 2b ce ac 32 c2 aa e2 fa 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}