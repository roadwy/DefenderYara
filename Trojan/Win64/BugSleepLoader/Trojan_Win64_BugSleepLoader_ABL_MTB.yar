
rule Trojan_Win64_BugSleepLoader_ABL_MTB{
	meta:
		description = "Trojan:Win64/BugSleepLoader.ABL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {4c 8b f0 f2 0f 11 44 24 20 80 44 24 20 fb 80 44 24 21 fb 80 44 24 22 fb 80 44 24 23 fb 80 44 24 24 fb 80 44 24 25 fb 80 44 24 26 fb 80 44 24 27 fb 66 89 4c 24 28 0f b6 0d ?? ?? ?? ?? 80 44 24 28 fb 80 44 24 29 fb 88 4c 24 2a 48 8b ce 41 ff d6 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}