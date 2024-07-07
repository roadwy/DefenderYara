
rule Trojan_Win32_GhostRAT_C_MTB{
	meta:
		description = "Trojan:Win32/GhostRAT.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c7 5f 5e 8b e5 5d 90 01 01 8a 04 39 2c 90 01 01 34 90 01 01 88 04 39 41 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}