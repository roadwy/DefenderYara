
rule Trojan_BAT_FileCoder_PMI_MTB{
	meta:
		description = "Trojan:BAT/FileCoder.PMI!MTB,SIGNATURE_TYPE_PEHSTR,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {4e 6f 43 72 79 20 52 61 6e 73 6f 6d 77 61 72 65 } //3 NoCry Ransomware
		$a_01_1 = {59 00 6f 00 75 00 20 00 68 00 61 00 76 00 65 00 20 00 62 00 65 00 65 00 6e 00 20 00 68 00 61 00 63 00 6b 00 65 00 64 00 } //2 You have been hacked
		$a_01_2 = {24 35 30 63 34 39 64 65 39 2d 39 31 34 61 2d 34 32 65 38 2d 61 39 66 36 2d 32 38 35 66 37 63 61 38 63 37 31 65 } //2 $50c49de9-914a-42e8-a9f6-285f7ca8c71e
		$a_01_3 = {79 00 6f 00 75 00 72 00 20 00 66 00 69 00 6c 00 65 00 73 00 20 00 68 00 61 00 76 00 65 00 20 00 62 00 65 00 65 00 6e 00 20 00 64 00 65 00 73 00 74 00 72 00 6f 00 79 00 65 00 64 00 } //1 your files have been destroyed
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=8
 
}