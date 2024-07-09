
rule Trojan_Win64_Bumblebee_MD_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.MD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 43 3c 0f af d0 48 8b 83 a0 00 00 00 88 14 01 44 8b 9b 98 00 00 00 ff 43 40 8b 83 f4 00 00 00 03 83 00 01 00 00 44 8b 83 bc 00 00 00 83 f0 01 01 83 e0 00 00 00 b8 ?? ?? ?? ?? 8b 93 e0 00 00 00 41 2b c0 03 93 08 01 00 00 01 43 28 83 f2 01 8b 73 40 44 0f af da 44 89 9b 98 00 00 00 49 81 fa ?? ?? ?? ?? 0f 8c } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}