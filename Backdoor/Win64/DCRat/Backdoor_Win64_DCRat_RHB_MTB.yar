
rule Backdoor_Win64_DCRat_RHB_MTB{
	meta:
		description = "Backdoor:Win64/DCRat.RHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {44 65 61 64 42 6f 74 } //1 DeadBot
		$a_01_1 = {4d 61 6c 77 61 72 65 } //1 Malware
		$a_00_2 = {4e 00 61 00 74 00 69 00 76 00 65 00 4c 00 6f 00 61 00 64 00 65 00 72 00 } //1 NativeLoader
		$a_03_3 = {50 45 00 00 64 86 06 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 02 0e 27 00 46 00 00 00 0c 06 00 00 00 00 00 40 46 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_03_3  & 1)*2) >=5
 
}