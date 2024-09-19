
rule Trojan_Win64_Redline_GXL_MTB{
	meta:
		description = "Trojan:Win64/Redline.GXL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 83 ec 28 48 8b 0d ?? ?? ?? ?? ba fe 05 00 00 ff 15 ?? ?? ?? ?? 83 3d 9b 41 ?? ?? 00 48 8b 0d ?? ?? ?? ?? 74 } //5
		$a_01_1 = {43 0f b6 14 11 41 8a c1 83 e0 0f 0f b6 0c 18 32 ca 43 88 0c 11 4d 85 c9 74 07 41 32 cb 43 88 0c 11 44 0f b6 da 49 83 c1 01 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}