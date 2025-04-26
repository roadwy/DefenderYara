
rule Trojan_Win64_Shelm_ABS_MTB{
	meta:
		description = "Trojan:Win64/Shelm.ABS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 fc 48 98 48 8d 15 ?? ?? ?? ?? 0f b6 04 10 32 45 fb 89 c1 8b 45 fc 48 98 48 8d 15 ?? ?? ?? ?? 88 0c 10 83 45 fc 01 8b 45 fc 3d ?? ?? ?? ?? ?? ?? 41 b9 40 00 00 00 41 b8 00 10 00 00 ba ?? ?? ?? ?? b9 00 00 00 00 48 8b 05 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}