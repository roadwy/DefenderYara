
rule Trojan_Win32_RedLineStealer_G_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 c2 0f b6 c0 0f b6 84 05 ?? ?? ?? ?? 30 83 ?? ?? ?? ?? 43 81 fb } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}