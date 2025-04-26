
rule Trojan_Win32_Racealer_PVK_MTB{
	meta:
		description = "Trojan:Win32/Racealer.PVK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b c3 c1 e8 05 03 44 24 ?? 03 d3 33 ca 81 3d ?? ?? ?? ?? 72 07 00 00 c7 05 ?? ?? ?? ?? b4 1a 3a df 89 35 ?? ?? ?? ?? 89 35 ?? ?? ?? ?? 89 4c 24 ?? 75 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}