
rule Backdoor_Win32_PcClient_gen_D{
	meta:
		description = "Backdoor:Win32/PcClient.gen!D,SIGNATURE_TYPE_PEHSTR_EXT,16 00 15 00 04 00 00 "
		
	strings :
		$a_00_0 = {64 72 69 76 65 72 73 5c } //1 drivers\
		$a_00_1 = {44 6f 53 65 72 76 69 63 65 } //1 DoService
		$a_03_2 = {33 c9 39 4c 24 08 76 10 8b 44 24 04 03 c1 80 30 90 01 01 41 3b 4c 24 08 72 f0 c3 90 00 } //10
		$a_03_3 = {83 c8 ff eb 1c 68 90 01 05 ff 15 90 01 04 85 c0 74 03 90 01 01 ff d0 90 01 01 ff 15 90 01 04 33 c0 90 00 } //10
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*10+(#a_03_3  & 1)*10) >=21
 
}