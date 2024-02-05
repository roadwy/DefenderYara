
rule Trojan_Win32_Guloader_SIBM13_MTB{
	meta:
		description = "Trojan:Win32/Guloader.SIBM13!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {66 0f 6e cb 90 02 0a 50 90 02 0a 31 f6 90 02 0a ff 34 30 90 02 0a 5b 90 02 0a 66 0f 6e eb 90 02 0a 90 18 90 02 0a 66 0f ef e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}