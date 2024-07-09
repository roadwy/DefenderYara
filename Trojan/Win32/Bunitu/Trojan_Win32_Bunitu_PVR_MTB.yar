
rule Trojan_Win32_Bunitu_PVR_MTB{
	meta:
		description = "Trojan:Win32/Bunitu.PVR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b c8 8b d1 89 15 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 89 02 5f 8b e5 5d 90 09 0a 00 8b c7 eb ?? 33 05 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}