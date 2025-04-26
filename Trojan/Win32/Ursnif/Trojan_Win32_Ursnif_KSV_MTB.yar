
rule Trojan_Win32_Ursnif_KSV_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.KSV!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 44 24 14 8b 16 02 c3 0f b6 c8 8b 44 24 10 d3 ca 33 d0 2b d3 89 16 83 c6 04 4b 75 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}