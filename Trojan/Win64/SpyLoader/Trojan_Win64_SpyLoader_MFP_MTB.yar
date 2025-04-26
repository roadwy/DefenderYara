
rule Trojan_Win64_SpyLoader_MFP_MTB{
	meta:
		description = "Trojan:Win64/SpyLoader.MFP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {58 48 89 4c 24 08 48 89 54 24 10 4c 89 44 24 18 4c 89 4c 24 20 48 83 ec 28 8b 0d ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 83 c4 28 48 8b 4c 24 08 48 8b 54 24 10 4c 8b 44 24 18 4c 8b 4c 24 20 49 89 ca 0f 05 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}