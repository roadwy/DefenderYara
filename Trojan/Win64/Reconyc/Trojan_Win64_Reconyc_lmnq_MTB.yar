
rule Trojan_Win64_Reconyc_lmnq_MTB{
	meta:
		description = "Trojan:Win64/Reconyc.lmnq!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 03 00 00 "
		
	strings :
		$a_02_0 = {2a a0 db df 45 f5 33 b6 ?? ?? ?? ?? 6b e5 59 d3 e0 33 a8 ?? ?? ?? ?? e0 f1 64 b7 02 30 8a ?? ?? ?? ?? 7c e4 } //10
		$a_81_1 = {73 6c 6f 61 64 65 72 2e 65 78 65 } //2 sloader.exe
		$a_81_2 = {53 68 65 6c 6c 45 78 65 63 75 74 65 45 78 57 } //2 ShellExecuteExW
	condition:
		((#a_02_0  & 1)*10+(#a_81_1  & 1)*2+(#a_81_2  & 1)*2) >=14
 
}