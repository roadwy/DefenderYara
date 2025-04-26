
rule Trojan_Win64_ShellcodeInject_DA_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeInject.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_03_0 = {0f b6 04 0b 40 30 f0 41 88 04 ?? 0f b6 44 0b 01 40 30 f0 41 88 44 ?? 01 0f b6 44 0b 02 40 30 f0 41 88 44 ?? 02 0f b6 44 0b 03 40 30 f0 41 88 44 ?? 03 48 83 c1 04 ?? 39 ?? 75 } //10
		$a_03_1 = {41 0f b6 04 ?? 40 30 f0 41 88 04 ?? 41 0f b6 44 ?? 01 40 30 f0 41 88 44 ?? 01 41 0f b6 44 ?? 02 40 30 f0 41 88 44 ?? 02 41 0f b6 44 ?? 03 40 30 f0 41 88 44 ?? 03 48 83 c1 04 ?? 39 ?? 75 } //10
		$a_80_2 = {73 68 65 6c 6c 63 6f 64 65 2e 70 64 62 } //shellcode.pdb  1
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10+(#a_80_2  & 1)*1) >=11
 
}