
rule Trojan_Win32_Yakes_DSP_MTB{
	meta:
		description = "Trojan:Win32/Yakes.DSP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 02 00 "
		
	strings :
		$a_02_0 = {81 c1 34 d4 00 00 89 8d 90 01 02 ff ff 8b 55 f8 8b 02 33 85 90 01 02 ff ff 8b 4d f8 89 01 90 09 06 00 8b 0d 90 00 } //02 00 
		$a_02_1 = {8b 45 f8 33 45 f0 89 45 f8 c7 85 90 01 01 fc ff ff 8d 00 00 00 8b 0d 90 01 04 8b 55 f8 89 11 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}