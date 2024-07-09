
rule TrojanDropper_Win32_Bunitu_MZ_MTB{
	meta:
		description = "TrojanDropper:Win32/Bunitu.MZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b c8 8b d1 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 08 5f 5d c3 90 09 06 00 33 05 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}