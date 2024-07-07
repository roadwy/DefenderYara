
rule Trojan_Win64_CobaltStrike_BRV_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.BRV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {43 61 6c 6c 44 4c 4c 44 79 6e 61 6d 69 63 2e 70 64 62 } //1 CallDLLDynamic.pdb
		$a_01_1 = {70 65 72 5f 74 68 72 65 61 64 5f 64 61 74 61 2e 63 70 70 } //1 per_thread_data.cpp
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}