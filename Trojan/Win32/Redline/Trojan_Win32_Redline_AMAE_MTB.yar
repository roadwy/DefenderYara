
rule Trojan_Win32_Redline_AMAE_MTB{
	meta:
		description = "Trojan:Win32/Redline.AMAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {59 8d 4c 24 90 01 01 8a 44 04 90 01 01 30 85 90 01 04 e8 90 01 04 8b 74 24 90 01 01 45 81 fd 90 01 03 00 0f 8c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}