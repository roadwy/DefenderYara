
rule Backdoor_BAT_Noancooe_C{
	meta:
		description = "Backdoor:BAT/Noancooe.C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {4e 61 6e 6f 43 6f 72 65 2e 43 6c 69 65 6e 74 50 6c 75 67 69 6e 48 6f 73 74 } //1 NanoCore.ClientPluginHost
		$a_03_1 = {07 1f 0b 58 06 1d 58 61 d2 ?? 2d 1d 26 02 16 91 02 18 91 1e 62 60 08 19 62 58 0d 16 13 04 16 13 05 2b 4f 0a 2b d3 0b 2b d7 } //1
		$a_01_2 = {06 1f 14 58 18 2d 03 26 2b 03 0a 2b 00 06 07 31 df } //1
		$a_01_3 = {11 05 17 5f 2d 15 09 20 fd 43 03 00 5a 20 c3 9e 26 00 58 0d 09 1f 10 64 d1 13 04 11 04 d2 13 06 11 04 1e 63 d1 13 04 03 11 05 91 13 07 03 11 05 11 07 06 61 } //1
		$a_01_4 = {4e 61 6e 6f 43 6f 72 65 20 43 6c 69 65 6e 74 } //1 NanoCore Client
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=3
 
}