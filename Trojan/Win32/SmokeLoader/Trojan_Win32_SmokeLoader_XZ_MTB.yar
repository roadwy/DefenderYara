
rule Trojan_Win32_SmokeLoader_XZ_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.XZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {2a 39 39 c6 6a ?? b4 ?? c5 69 ?? 4c 29 c6 4c 35 ?? ?? ?? ?? c6 c6 ?? f9 4d 34 ?? 4c 2d ?? ?? ?? ?? 6a } //1
		$a_03_1 = {33 31 b8 d7 ?? ?? ?? 39 d2 3c ?? d2 cc 31 11 d2 3c 39 0b 55 ?? d4 ?? ff 9c } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}