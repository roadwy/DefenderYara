
rule Trojan_Win32_Azorult_YP_MTB{
	meta:
		description = "Trojan:Win32/Azorult.YP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {69 c9 fd 43 03 00 89 0d ?? ?? ?? ?? 81 05 ?? ?? ?? ?? c3 9e 26 00 81 3d ?? ?? ?? ?? cf 12 00 00 0f b7 1d ?? ?? ?? ?? 75 0a 6a 00 6a 00 ff 15 ?? ?? ?? ?? 8b 45 f8 30 1c 06 46 3b f7 7c 8e } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}