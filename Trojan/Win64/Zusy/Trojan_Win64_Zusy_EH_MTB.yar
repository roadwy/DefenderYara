
rule Trojan_Win64_Zusy_EH_MTB{
	meta:
		description = "Trojan:Win64/Zusy.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 83 eb 05 b9 58 20 99 00 48 29 cb 50 b8 86 15 1c 00 48 01 d8 83 38 00 } //3
	condition:
		((#a_01_0  & 1)*3) >=3
 
}
rule Trojan_Win64_Zusy_EH_MTB_2{
	meta:
		description = "Trojan:Win64/Zusy.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {2e 74 68 65 6d 69 64 61 00 c0 76 00 00 80 18 00 00 00 00 00 00 58 0d } //1
		$a_01_1 = {44 00 56 00 44 00 53 00 65 00 74 00 75 00 70 00 2e 00 65 00 78 00 65 00 } //1 DVDSetup.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}