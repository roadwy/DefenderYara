
rule Trojan_Win64_Amadey_BS_MTB{
	meta:
		description = "Trojan:Win64/Amadey.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {4c 0f 47 45 c8 ba 12 27 00 00 48 8b c8 e8 ?? ?? 00 00 4c 8d 05 ?? ?? ff ff ba 2b 4e 00 00 48 8b cb e8 ?? ?? 00 00 4c 8d 45 a8 ba 11 27 00 00 48 8b cb } //4
		$a_03_1 = {0f b6 c1 2a c2 04 ?? 41 30 01 ff c1 4d 8d 49 01 83 f9 } //1
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*1) >=5
 
}