
rule Trojan_Win64_Mikey_HMZ_MTB{
	meta:
		description = "Trojan:Win64/Mikey.HMZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {44 89 e7 4c 8b a4 24 ?? ?? ?? ?? 41 30 04 24 49 ff c4 4c 89 a4 24 ?? ?? ?? ?? 4c 3b a4 24 58 01 00 00 48 b8 aa a2 91 e3 af 8c 39 12 4d 89 fc 49 89 d7 48 ba 83 8e 8e dd af 8c 39 12 48 0f 44 c2 4c 89 fa 4d 89 e7 41 89 fc 48 89 cf e9 ba } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}