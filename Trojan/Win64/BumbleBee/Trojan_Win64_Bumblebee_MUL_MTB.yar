
rule Trojan_Win64_Bumblebee_MUL_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.MUL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {4d 8d 0c 03 4d 2b f3 49 8b f3 4c 89 b4 24 ?? ?? ?? ?? 4c 2b c0 43 8a 0c 0e 2a 8c 24 ?? ?? ?? ?? 32 8c 24 ?? ?? ?? ?? 49 8b 42 48 41 88 0c 01 83 ff ?? 0f 84 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}