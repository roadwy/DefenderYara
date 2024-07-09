
rule Backdoor_Win32_Farfli_GMF_MTB{
	meta:
		description = "Backdoor:Win32/Farfli.GMF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {43 6f 6e 6e c7 45 ?? 65 63 74 00 c7 45 ?? 46 74 70 4f c7 45 ?? 70 65 6e 46 c7 45 ?? 69 6c 65 00 c7 45 ?? 49 6e 74 65 c7 45 ?? 72 6e 65 74 c7 45 ?? 52 65 61 64 c7 45 ?? 46 69 6c 65 88 5d ?? ff 15 ?? ?? ?? ?? 89 85 } //10
		$a_80_1 = {7a 68 75 2e 65 78 65 } //zhu.exe  1
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*1) >=11
 
}