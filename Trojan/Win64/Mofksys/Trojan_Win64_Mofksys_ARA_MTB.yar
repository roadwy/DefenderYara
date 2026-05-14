
rule Trojan_Win64_Mofksys_ARA_MTB{
	meta:
		description = "Trojan:Win64/Mofksys.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {44 0f b6 0f 41 80 f1 55 48 8b 4b 10 48 8b 53 18 48 3b ca 73 1f 48 8d 41 01 48 89 43 10 48 8b c3 48 83 fa ?? ?? 03 48 8b 03 44 88 0c 08 c6 44 08 01 00 eb 08 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}