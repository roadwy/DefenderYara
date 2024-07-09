
rule Trojan_Win32_Vidar_DE_MTB{
	meta:
		description = "Trojan:Win32/Vidar.DE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 44 3c ?? 03 c6 0f b6 c0 59 8a 44 04 ?? 30 85 00 ?? ?? ?? 45 81 fd 00 ?? ?? ?? 7c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}