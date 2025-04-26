
rule Trojan_Win32_Ursnif_PVD_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.PVD!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {88 54 24 11 8a d6 80 e2 f0 88 74 24 10 c0 e2 02 0a 14 38 88 54 24 12 8a d6 80 e2 fc c0 e2 04 0a 54 38 01 88 54 24 13 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}