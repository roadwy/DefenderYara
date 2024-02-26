
rule Trojan_Win32_Zusy_AZS_MTB{
	meta:
		description = "Trojan:Win32/Zusy.AZS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 56 0e 8d 76 10 8b c2 47 c1 e8 18 0f b6 0c 85 70 5c 5f 00 0f b6 46 ff 8b 0c 8d 70 50 5f 00 0f b6 04 85 70 5c 5f 00 33 0c 85 70 48 5f 00 0f b6 c2 } //00 00 
	condition:
		any of ($a_*)
 
}