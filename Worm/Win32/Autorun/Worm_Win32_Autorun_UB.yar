
rule Worm_Win32_Autorun_UB{
	meta:
		description = "Worm:Win32/Autorun.UB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {eb 44 53 e8 90 01 04 83 f8 02 75 36 8a 03 3c 41 74 30 3c 42 74 2c 90 00 } //1
		$a_03_1 = {83 f0 04 83 f0 02 83 f0 01 50 8b 45 ec 8b 04 98 e8 90 01 04 50 e8 90 00 } //1
		$a_00_2 = {5b 61 75 74 6f 72 75 6e 5d 00 } //1 慛瑵牯湵]
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}