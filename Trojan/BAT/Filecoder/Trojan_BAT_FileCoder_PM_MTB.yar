
rule Trojan_BAT_FileCoder_PM_MTB{
	meta:
		description = "Trojan:BAT/FileCoder.PM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {00 dc 06 07 28 ?? 00 00 06 0c 02 08 28 ?? 00 00 0a 00 02 02 72 ?? 00 00 70 28 ?? 00 00 0a 28 ?? 00 00 0a 00 2a } //2
		$a_00_1 = {2e 00 6c 00 6f 00 63 00 6b 00 65 00 64 00 } //2 .locked
		$a_01_2 = {46 00 69 00 6c 00 65 00 73 00 20 00 68 00 61 00 76 00 65 00 20 00 62 00 65 00 65 00 6e 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 } //1 Files have been encrypted
	condition:
		((#a_03_0  & 1)*2+(#a_00_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}