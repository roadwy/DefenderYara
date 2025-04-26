
rule Trojan_Win64_Rozena_HNJ_MTB{
	meta:
		description = "Trojan:Win64/Rozena.HNJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c7 44 24 40 57 00 73 00 48 05 ?? ?? 00 00 c7 44 24 44 32 00 5f 00 48 ba ?? ?? ?? ?? 90 90 51 b1 56 c7 44 24 48 33 00 32 00 c7 44 24 4c 2e 00 64 00 c7 44 24 50 6c 00 6c 00 4c 8d 78 01 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}