
rule Trojan_Win32_Vidar_SPGH_MTB{
	meta:
		description = "Trojan:Win32/Vidar.SPGH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c0 64 89 44 24 10 83 6c 24 10 64 8a 54 24 10 8b 44 24 14 30 14 30 83 bc 24 ?? ?? ?? ?? 0f 75 ?? 6a 00 6a 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}