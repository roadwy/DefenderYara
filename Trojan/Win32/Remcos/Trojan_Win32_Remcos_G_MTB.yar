
rule Trojan_Win32_Remcos_G_MTB{
	meta:
		description = "Trojan:Win32/Remcos.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c6 04 24 65 8b d3 90 02 01 8b fe 03 fa 8a 90 90 90 02 04 90 02 02 32 14 24 88 17 40 40 90 02 02 43 81 fb 66 5e 00 00 75 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}