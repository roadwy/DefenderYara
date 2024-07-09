
rule Trojan_Win32_SmokeLoader_AL_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.AL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 ea 03 c6 89 45 e8 03 55 cc 8b 45 e8 31 45 fc 31 55 fc 89 3d ?? ?? ?? ?? 8b 45 f4 89 45 e4 8b 45 fc 29 45 e4 8b 45 e4 89 45 f4 8b 45 c8 29 45 f8 ff 4d dc 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}