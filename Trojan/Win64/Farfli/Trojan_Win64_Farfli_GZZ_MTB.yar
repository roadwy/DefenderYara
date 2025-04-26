
rule Trojan_Win64_Farfli_GZZ_MTB{
	meta:
		description = "Trojan:Win64/Farfli.GZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {57 69 6e 64 6f 77 73 5c 54 65 6d 70 5c 75 70 67 72 61 64 65 72 2e 62 61 63 6b } //Windows\Temp\upgrader.back  1
		$a_01_1 = {61 00 70 00 69 00 2e 00 62 00 75 00 79 00 33 00 37 00 32 00 31 00 2e 00 6e 00 65 00 74 00 } //1 api.buy3721.net
		$a_80_2 = {36 34 42 34 36 55 64 35 4b 4d 68 36 76 71 78 37 74 5a 38 72 78 39 44 78 58 30 34 73 } //64B46Ud5KMh6vqx7tZ8rx9DxX04s  1
		$a_80_3 = {77 73 63 72 69 70 74 2e 65 78 65 20 2f 2f 45 3a 76 62 73 63 72 69 70 74 } //wscript.exe //E:vbscript  1
		$a_80_4 = {62 61 69 64 75 53 61 66 65 54 72 61 79 2e 65 78 65 } //baiduSafeTray.exe  1
	condition:
		((#a_80_0  & 1)*1+(#a_01_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}