
rule Trojan_Win32_SmokeLoader_MJO_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.MJO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 c1 e0 ?? 03 45 ?? 8d 0c 33 33 c1 33 45 ?? 81 c3 ?? ?? ?? ?? 2b f8 ff 4d ?? 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}