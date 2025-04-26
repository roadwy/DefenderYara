
rule Trojan_Win64_NetLoader_NLA_MTB{
	meta:
		description = "Trojan:Win64/NetLoader.NLA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 5d f4 89 55 fc 74 52 48 83 0d 6a 0c 02 00 ?? 41 83 c8 04 25 ?? ?? ?? ?? 44 89 05 3a 31 02 00 3d ?? ?? ?? ?? 74 28 3d 60 06 02 00 74 21 } //5
		$a_01_1 = {57 49 4e 37 32 4b 38 52 32 } //1 WIN72K8R2
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}