
rule Trojan_Win32_Upatre_AHD_MTB{
	meta:
		description = "Trojan:Win32/Upatre.AHD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 03 8b 4d 10 8b 55 0c 89 0c 90 90 42 89 55 0c 4e 83 fe } //20
		$a_03_1 = {41 01 c0 e8 ?? 0f b6 c0 09 c2 0f b6 82 ?? ?? ?? ?? 88 43 ?? 89 f8 29 f0 83 f8 ?? 74 } //30
	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*30) >=50
 
}