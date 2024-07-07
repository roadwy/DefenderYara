
rule Trojan_Win32_Windigo_AMAE_MTB{
	meta:
		description = "Trojan:Win32/Windigo.AMAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 e8 89 45 90 01 01 8b 45 90 01 01 01 45 90 01 01 8b 45 90 01 01 33 45 90 01 01 81 3d 90 01 04 03 0b 00 00 89 45 90 01 01 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}