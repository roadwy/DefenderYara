
rule Trojan_Win64_ShellcodeRunner_AHB_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.AHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 03 00 00 "
		
	strings :
		$a_01_0 = {48 89 85 88 00 00 00 48 8d 55 28 48 8d 4d 58 ff 95 88 00 00 00 } //10
		$a_03_1 = {c7 45 04 00 00 00 00 8b 85 ?? ?? 00 00 89 45 28 8b 85 98 01 00 00 89 45 2c 48 8b 85 90 00 } //5
		$a_01_2 = {73 50 61 79 6c 6f 61 64 53 69 7a 65 00 00 00 00 70 50 61 79 6c 6f 61 64 44 61 74 61 } //1
	condition:
		((#a_01_0  & 1)*10+(#a_03_1  & 1)*5+(#a_01_2  & 1)*1) >=16
 
}