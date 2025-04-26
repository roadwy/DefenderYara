
rule Trojan_Win64_Zusy_SAI_MTB{
	meta:
		description = "Trojan:Win64/Zusy.SAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {e8 9c 41 00 00 48 8b 44 24 70 48 63 48 04 48 8d 3d ?? ?? ?? 00 48 89 7c 0c 70 48 8b 44 24 70 48 63 48 04 8d ?? ?? ?? ff ff 89 54 0c 6c 48 8b cb 48 83 7d f8 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}