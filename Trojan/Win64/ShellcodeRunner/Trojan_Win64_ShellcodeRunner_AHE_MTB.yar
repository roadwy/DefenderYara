
rule Trojan_Win64_ShellcodeRunner_AHE_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.AHE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_01_0 = {78 6f 72 5f 64 61 74 61 2e 64 61 74 } //20 xor_data.dat
		$a_03_1 = {4d 8d 04 39 49 8b ?? 49 [0-06] 49 [0-06] 49 [0-0a] 48 ?? ?? ?? 48 ?? ?? ?? 48 2b c8 [0-03] 0f b6 [0-03] 43 32 04 ?? 41 88 00 4c 3b } //30
	condition:
		((#a_01_0  & 1)*20+(#a_03_1  & 1)*30) >=50
 
}