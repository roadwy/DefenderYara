
rule Trojan_Win32_ModiLoader_AMBF_MTB{
	meta:
		description = "Trojan:Win32/ModiLoader.AMBF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 38 ff 57 0c 8b 85 90 01 04 8b 15 90 01 04 0f b6 44 10 ff 0f b6 c0 33 d2 05 90 01 04 83 d2 00 8b d0 8d 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}