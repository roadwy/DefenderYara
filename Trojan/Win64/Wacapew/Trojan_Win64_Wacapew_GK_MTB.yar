
rule Trojan_Win64_Wacapew_GK_MTB{
	meta:
		description = "Trojan:Win64/Wacapew.GK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 f0 3d 48 63 4c 24 20 88 84 0c ?? ?? ?? ?? 48 63 44 24 20 0f b6 84 04 ?? ?? ?? ?? 05 8e 00 00 00 48 63 4c 24 20 88 84 0c ?? ?? ?? ?? 48 63 44 24 20 0f b6 84 04 ?? ?? ?? ?? 05 82 00 00 00 48 63 4c 24 20 88 84 0c ?? ?? ?? ?? 48 63 44 24 20 0f b6 84 04 ?? ?? ?? ?? 05 ae 00 00 00 48 63 4c 24 20 88 84 0c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}