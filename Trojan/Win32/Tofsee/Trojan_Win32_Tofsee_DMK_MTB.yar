
rule Trojan_Win32_Tofsee_DMK_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.DMK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c2 d3 e8 03 fa 03 45 d4 33 c7 31 45 fc ff 75 fc 8b c3 e8 ?? ?? ?? ?? 8b d8 8d 45 f0 e8 ?? ?? ?? ?? ff 4d e8 0f 85 ?? ?? ?? ?? 81 3d ?? ?? ?? ?? 6d 0a 00 00 8b 7d 08 89 1f 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}