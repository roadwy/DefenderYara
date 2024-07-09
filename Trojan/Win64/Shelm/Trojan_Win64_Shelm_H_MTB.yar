
rule Trojan_Win64_Shelm_H_MTB{
	meta:
		description = "Trojan:Win64/Shelm.H!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {4c 8b 44 24 ?? 48 8b 4c 24 ?? ba 10 66 00 00 45 31 c9 48 8d 44 24 ?? 48 89 44 24 } //2
		$a_03_1 = {4c 8b 54 24 ?? 48 8b 4c 24 ?? 31 c0 89 c2 45 31 c9 48 8d 44 24 ?? 45 89 c8 4c 89 54 24 ?? 48 89 44 24 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}