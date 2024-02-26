
rule Trojan_Win32_IcLoader_RG_MTB{
	meta:
		description = "Trojan:Win32/IcLoader.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {ff 15 3c 40 65 00 8b 4c 24 14 51 ff 15 3c 40 65 00 5f 5e 5b 83 c4 10 c3 90 90 90 55 8b ec 51 68 90 b9 85 00 e8 12 fe ff ff e9 } //00 00 
	condition:
		any of ($a_*)
 
}