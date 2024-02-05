
rule Trojan_Win32_Gepys_PVR_MTB{
	meta:
		description = "Trojan:Win32/Gepys.PVR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_02_0 = {89 c2 80 ca 01 0f af 55 fc 29 d0 8b 55 e0 01 c2 8b 45 e4 d3 e0 03 45 e0 ff 45 f4 e8 90 01 04 81 7d f4 e8 07 00 00 7d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}