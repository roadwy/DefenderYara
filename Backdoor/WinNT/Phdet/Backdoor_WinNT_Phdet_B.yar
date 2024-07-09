
rule Backdoor_WinNT_Phdet_B{
	meta:
		description = "Backdoor:WinNT/Phdet.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_07_0 = {eb 0c 58 2b 05 ?? ?? ?? ?? 03 45 f8 ff e0 58 } //3
		$a_03_1 = {81 e1 00 f0 ff ff 90 09 06 00 8b ?? ?? 8b ?? 04 } //1
		$a_03_2 = {81 e2 00 f0 ff ff 90 09 06 00 8b ?? ?? 8b ?? 04 } //1
		$a_03_3 = {25 00 f0 ff ff 90 09 06 00 8b ?? ?? 8b ?? 04 } //1
	condition:
		((#a_07_0  & 1)*3+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}