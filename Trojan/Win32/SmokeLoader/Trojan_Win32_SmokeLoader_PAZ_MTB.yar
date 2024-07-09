
rule Trojan_Win32_SmokeLoader_PAZ_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.PAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 c1 e0 04 89 45 08 8b 45 e8 01 45 08 83 0d ?? ?? ?? ?? ?? 8b c6 c1 e8 05 03 45 e4 03 fe 31 7d 08 50 89 45 0c 8d 45 08 50 c7 05 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}