
rule Trojan_Win32_Stealc_CA_MTB{
	meta:
		description = "Trojan:Win32/Stealc.CA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 4d f4 8b 7d f0 8b d3 d3 ea 8d 04 1f 89 45 ec c7 05 ?? ?? ?? ?? ee 3d ea f4 03 55 d4 8b 45 ec 31 45 fc 33 55 fc 81 3d ?? ?? ?? ?? 13 02 00 00 89 55 ec 75 0c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}