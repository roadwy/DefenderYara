
rule Trojan_Win64_Tedy_LMU_MTB{
	meta:
		description = "Trojan:Win64/Tedy.LMU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 89 44 24 60 33 d2 48 8b 4c 24 60 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 33 d2 b9 b8 ?? ?? ?? f7 f1 8b c2 05 e8 03 00 00 8b c8 ?? ?? ?? ?? ?? ?? c7 44 24 20 00 00 00 00 45 33 c9 45 33 c0 33 d2 48 8d 0d a3 8e 01 } //20
		$a_81_1 = {73 68 65 6c 6c 63 6f 64 65 2e 64 61 74 } //15 shellcode.dat
	condition:
		((#a_03_0  & 1)*20+(#a_81_1  & 1)*15) >=35
 
}