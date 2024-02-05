
rule Trojan_Win32_IcedID_PCA_MTB{
	meta:
		description = "Trojan:Win32/IcedID.PCA!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b c1 48 63 0c 24 eb 08 8b c2 48 98 3a c9 74 16 48 8b 54 24 40 88 04 0a eb 2e eb 3e 8b 4c 24 04 33 c8 3a c9 74 da } //00 00 
	condition:
		any of ($a_*)
 
}