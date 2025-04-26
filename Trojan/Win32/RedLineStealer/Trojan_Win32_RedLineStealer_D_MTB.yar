
rule Trojan_Win32_RedLineStealer_D_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 c2 0f b6 c0 0f b6 84 05 ?? ?? ?? ?? 30 81 ?? ?? ?? ?? 41 89 8d } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}