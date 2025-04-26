
rule Trojan_Win32_Ekstak_BC_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.BC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 f0 03 c1 42 8a 1c 0e 8b 75 0c 88 1c 30 8a 81 ?? ?? ?? ?? 84 c0 75 ?? a1 ?? ?? ?? ?? 8a 1d ?? ?? ?? ?? 03 c1 03 c6 30 18 83 3d ?? ?? ?? ?? 03 76 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}