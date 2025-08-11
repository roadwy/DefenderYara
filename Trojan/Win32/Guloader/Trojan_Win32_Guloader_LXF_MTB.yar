
rule Trojan_Win32_Guloader_LXF_MTB{
	meta:
		description = "Trojan:Win32/Guloader.LXF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {73 6b 75 65 73 70 69 6c 6b 75 6e 73 74 73 2e 74 68 65 } //1 skuespilkunsts.the
		$a_81_1 = {64 61 6d 65 62 6c 61 64 73 6c 73 65 72 65 6e 73 2e 6a 70 67 } //1 damebladslserens.jpg
		$a_81_2 = {54 72 6f 6c 6c 65 79 62 75 73 31 39 33 2e 74 78 74 } //1 Trolleybus193.txt
		$a_81_3 = {4d 61 72 69 65 68 6e 65 72 73 2e 70 6c 65 } //1 Mariehners.ple
		$a_81_4 = {4b 61 74 69 61 73 2e 74 78 74 } //1 Katias.txt
		$a_81_5 = {48 65 73 74 65 70 72 65 72 31 32 37 2e 6a 70 67 } //1 Hesteprer127.jpg
		$a_81_6 = {62 6c 61 64 66 64 64 65 72 2e 65 78 65 } //1 bladfdder.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}