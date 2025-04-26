
rule Trojan_Win32_SmokeLoader_M_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.M!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c7 89 44 24 10 8b 44 24 18 31 44 24 10 8b 44 24 10 29 44 24 1c 81 c6 ?? ?? ?? ?? ff 4c 24 24 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}