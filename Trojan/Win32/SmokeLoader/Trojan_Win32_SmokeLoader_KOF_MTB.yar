
rule Trojan_Win32_SmokeLoader_KOF_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.KOF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {50 89 7d f8 e8 ?? ?? ?? ?? 8a 45 f8 30 04 33 83 7d 08 0f 59 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}