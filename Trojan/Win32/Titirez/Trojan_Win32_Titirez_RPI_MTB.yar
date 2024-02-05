
rule Trojan_Win32_Titirez_RPI_MTB{
	meta:
		description = "Trojan:Win32/Titirez.RPI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {0f b6 05 04 70 56 00 8b 0d bc 82 56 00 03 8d cc fe ff ff 0f b6 11 33 d0 a1 bc 82 56 00 03 85 cc fe ff ff 88 10 } //00 00 
	condition:
		any of ($a_*)
 
}