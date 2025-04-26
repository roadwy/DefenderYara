
rule Trojan_Win64_Tedy_A_MTB{
	meta:
		description = "Trojan:Win64/Tedy.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {66 44 39 65 06 74 39 48 03 fd 8b 47 fc 85 c0 74 21 44 8b 07 44 8b c8 8b 57 f8 4d 03 c7 49 03 d6 4c 89 64 24 20 48 8b cb ff 15 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}