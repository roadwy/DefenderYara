
rule Trojan_Win32_Waldek_GKI_MTB{
	meta:
		description = "Trojan:Win32/Waldek.GKI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 ca 0f b6 d3 0f af d1 02 14 33 43 32 c2 8b 54 24 90 01 01 83 fb 90 01 01 7c 90 01 01 88 04 3a 42 89 54 24 90 01 01 3b d5 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}