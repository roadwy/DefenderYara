
rule Trojan_Win32_Amadey_YAH_MTB{
	meta:
		description = "Trojan:Win32/Amadey.YAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 6c 33 c3 2b f0 89 b5 94 fd ff ff } //1
		$a_03_1 = {03 cf 89 45 6c 8b 85 ?? ?? ?? ?? 01 45 6c 8b df c1 e3 04 03 9d ?? ?? ff ff 33 d9 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}