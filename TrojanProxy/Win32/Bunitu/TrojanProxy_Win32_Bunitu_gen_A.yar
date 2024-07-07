
rule TrojanProxy_Win32_Bunitu_gen_A{
	meta:
		description = "TrojanProxy:Win32/Bunitu.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_00_0 = {c6 41 06 4d c6 41 0f 53 c6 41 1f 53 } //2
		$a_00_1 = {c7 00 3a 2a 3a 45 5a } //5
		$a_00_2 = {c7 00 3b d1 39 f4 } //5
		$a_00_3 = {81 3e 73 61 6d 70 } //5
		$a_03_4 = {81 2c 24 61 75 17 00 8f 00 c7 40 04 90 01 04 ff 48 04 ff 48 04 81 68 04 5c 78 39 30 01 04 ff 48 04 90 00 } //2
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*5+(#a_00_2  & 1)*5+(#a_00_3  & 1)*5+(#a_03_4  & 1)*2) >=7
 
}