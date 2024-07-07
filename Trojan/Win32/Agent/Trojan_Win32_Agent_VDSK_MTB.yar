
rule Trojan_Win32_Agent_VDSK_MTB{
	meta:
		description = "Trojan:Win32/Agent.VDSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_02_0 = {8b 4c 24 10 81 c2 dc 22 6e 01 89 11 8b cf 2b cd 03 c9 2b c8 81 c1 a9 77 00 00 89 15 90 01 04 39 3d 90 00 } //2
		$a_00_1 = {66 8b 44 24 26 66 0b 44 24 26 8b 4c 24 10 66 89 44 24 26 8b 54 24 08 8a 1c 0a 8b 74 24 04 88 1c 0e } //2
		$a_02_2 = {81 ec 20 04 00 00 a1 90 01 04 33 c4 89 84 24 1c 04 00 00 81 3d 90 01 04 12 0f 00 00 75 90 00 } //2
	condition:
		((#a_02_0  & 1)*2+(#a_00_1  & 1)*2+(#a_02_2  & 1)*2) >=2
 
}