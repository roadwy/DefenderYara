
rule Trojan_Win64_Tedy_STAE_MTB{
	meta:
		description = "Trojan:Win64/Tedy.STAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 75 a7 48 8d 1d ba bb 00 00 0f 57 c0 0f 11 45 af 8b d6 48 89 55 bf 41 b8 0f 00 00 00 4c 89 45 c7 88 55 af c7 45 a7 01 00 00 00 b1 3e } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}