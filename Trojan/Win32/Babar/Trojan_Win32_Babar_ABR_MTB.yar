
rule Trojan_Win32_Babar_ABR_MTB{
	meta:
		description = "Trojan:Win32/Babar.ABR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 68 00 a0 00 00 8d 85 f4 5f ff ff 50 8b 45 fc 50 } //01 00 
		$a_01_1 = {83 c0 40 8d 95 f4 5f ff ff e8 17 c3 ed ff 8b 85 f0 5f ff ff 33 d2 89 50 3c 8b 85 f0 5f ff ff 33 d2 89 50 44 8b 85 f0 5f ff ff 33 d2 89 50 48 } //00 00 
	condition:
		any of ($a_*)
 
}