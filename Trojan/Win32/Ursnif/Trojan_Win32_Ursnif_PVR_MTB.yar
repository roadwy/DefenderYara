
rule Trojan_Win32_Ursnif_PVR_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.PVR!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 10 0f b6 c9 d3 ca 8b 4d f8 83 c0 04 33 d1 2b d3 89 50 fc 8b 55 f4 4b 75 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}