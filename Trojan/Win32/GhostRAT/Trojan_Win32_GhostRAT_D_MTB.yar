
rule Trojan_Win32_GhostRAT_D_MTB{
	meta:
		description = "Trojan:Win32/GhostRAT.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f be 08 81 e9 90 01 04 8b 55 90 01 01 03 55 90 01 01 88 0a 8b 45 90 01 01 03 45 90 01 01 0f be 08 83 f1 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}