
rule Trojan_Win64_Vidar_LR_MTB{
	meta:
		description = "Trojan:Win64/Vidar.LR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 03 00 00 "
		
	strings :
		$a_01_0 = {8a 0c 03 80 f1 e1 42 88 0c 30 48 ff c0 48 83 f8 0c } //10
		$a_03_1 = {41 8a 0c 07 80 f1 d5 48 8d ?? ?? ?? ?? ?? 88 0c 10 48 ff c0 48 83 f8 03 } //20
		$a_81_2 = {25 73 5c 25 73 3a 73 65 6e 64 } //5 %s\%s:send
	condition:
		((#a_01_0  & 1)*10+(#a_03_1  & 1)*20+(#a_81_2  & 1)*5) >=35
 
}