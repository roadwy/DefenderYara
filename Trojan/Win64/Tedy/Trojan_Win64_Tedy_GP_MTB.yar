
rule Trojan_Win64_Tedy_GP_MTB{
	meta:
		description = "Trojan:Win64/Tedy.GP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8d 41 aa 30 44 0d a8 48 ff c1 48 83 f9 30 72 f0 c6 45 d9 00 4c 89 7c 24 48 4c 89 7c 24 58 48 c7 44 24 60 0f } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}