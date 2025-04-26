
rule Backdoor_Win32_Pirpi_D{
	meta:
		description = "Backdoor:Win32/Pirpi.D,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 7c 24 1c 57 33 f6 ff d3 85 c0 75 1a 8b 2d e0 80 00 10 83 fe 14 7f 0f 68 ?? ?? 00 00 46 ff d5 57 ff d3 85 c0 74 ec } //1
		$a_03_1 = {8d 7c 24 0c f3 a5 8b b4 24 ?? ?? 00 00 85 ed 7e 21 8d 4c 24 0c 53 8a 9c 24 90 1b 00 00 00 8b c6 2b ce 8b fd 8a 14 01 32 d3 30 10 88 14 01 40 4f 75 f2 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}