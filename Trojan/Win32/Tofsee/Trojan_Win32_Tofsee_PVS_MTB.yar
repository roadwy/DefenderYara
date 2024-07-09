
rule Trojan_Win32_Tofsee_PVS_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.PVS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_02_0 = {0f b6 c3 03 f8 81 e7 ff 00 00 00 81 3d ?? ?? ?? ?? 81 0c 00 00 75 90 09 0c 00 a1 ?? ?? ?? ?? 0f b6 b8 } //1
		$a_02_1 = {30 04 1f 4f 79 90 09 05 00 e8 } //1
		$a_02_2 = {05 c3 9e 26 00 a3 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? a0 ?? ?? ?? ?? 30 04 1e 46 3b f7 7c } //2
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*2) >=2
 
}