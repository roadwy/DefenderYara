
rule Trojan_Win32_Cobaltstrike_DA_MTB{
	meta:
		description = "Trojan:Win32/Cobaltstrike.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b d9 83 e3 03 8a 1c 3b 8d 14 29 32 1c 10 41 3b ce 88 1a 7c 90 01 01 8b 54 24 18 8b 44 24 1c 5b 89 2a 5f 89 30 90 00 } //01 00 
		$a_03_1 = {03 c8 8a 4c 39 04 8b d0 83 e2 03 32 4c 14 14 40 3b c6 88 4c 18 ff 7c 90 09 06 00 8b 0d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}