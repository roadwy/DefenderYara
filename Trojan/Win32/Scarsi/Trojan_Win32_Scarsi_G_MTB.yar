
rule Trojan_Win32_Scarsi_G_MTB{
	meta:
		description = "Trojan:Win32/Scarsi.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {88 02 ff 45 90 01 01 81 7d 90 02 30 90 13 90 02 30 83 7d 90 02 30 8b 45 90 02 40 8b 45 90 01 01 8a 80 90 02 10 34 0d 8b 55 90 01 01 03 55 90 01 01 88 02 90 02 20 8b 45 90 01 01 8a 80 90 01 04 8b 55 90 01 01 03 55 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}