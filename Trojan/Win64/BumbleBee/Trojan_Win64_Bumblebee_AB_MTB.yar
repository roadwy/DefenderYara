
rule Trojan_Win64_Bumblebee_AB_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {42 8a 0c 30 2a 8c 24 a8 00 00 00 32 8c 24 a0 00 00 00 49 8b 40 20 41 88 0c 06 83 fd 08 0f 84 ?? ?? 00 00 49 8b 50 20 8b cd b8 01 00 00 00 } //1
		$a_03_1 = {49 8b 00 48 8b ce 48 81 c9 ?? ?? 00 00 48 0f af c1 49 89 00 49 8b 48 20 41 8a 04 0f 02 c0 [0-03] 41 88 04 0f e9 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}