
rule Trojan_Win64_VulDriveLoader_SA_MTB{
	meta:
		description = "Trojan:Win64/VulDriveLoader.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 ff c0 48 89 45 90 01 01 48 8b 45 90 01 01 48 39 45 90 01 01 73 90 01 01 48 8b 85 90 01 04 48 8b 4d 90 01 01 0f b7 04 48 0f b7 8d 90 01 04 33 c1 48 8b 4d 90 01 01 48 8b 55 90 01 01 66 89 04 51 eb 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}