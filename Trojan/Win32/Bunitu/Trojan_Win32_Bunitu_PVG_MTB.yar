
rule Trojan_Win32_Bunitu_PVG_MTB{
	meta:
		description = "Trojan:Win32/Bunitu.PVG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f be 0c 30 8b 55 e8 0f be 02 03 c1 8b 4d e8 88 01 8b 15 90 01 04 83 c2 01 89 15 90 01 04 e9 90 00 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}