
rule Trojan_Win32_Remcos_G_MTB{
	meta:
		description = "Trojan:Win32/Remcos.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c6 04 24 65 8b d3 [0-01] 8b fe 03 fa 8a 90 90 [0-04] [0-02] 32 14 24 88 17 40 40 [0-02] 43 81 fb 66 5e 00 00 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}