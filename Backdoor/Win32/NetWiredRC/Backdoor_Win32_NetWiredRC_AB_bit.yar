
rule Backdoor_Win32_NetWiredRC_AB_bit{
	meta:
		description = "Backdoor:Win32/NetWiredRC.AB!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 04 17 fe c0 88 04 17 29 c0 83 c0 06 89 c1 53 56 8a 44 0e ff 32 44 0f ff 5e 5b 3a 44 0b ff } //1
		$a_03_1 = {8a 44 0f ff 3c 7a 75 90 01 01 4a 8a 04 17 fe c0 88 04 17 3c 7b 75 90 01 01 c6 04 17 90 01 01 eb 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}