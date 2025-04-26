
rule Trojan_Win32_Racealer_MX_MTB{
	meta:
		description = "Trojan:Win32/Racealer.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b d6 c1 ea 05 03 54 24 ?? 89 54 24 24 3d 31 09 00 00 } //1
		$a_02_1 = {33 c1 2b f0 e8 ?? ?? ?? ?? 8b d6 8b c8 d3 e2 89 6c 24 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}