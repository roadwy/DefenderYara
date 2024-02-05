
rule Trojan_Win32_IcedId_DEO_MTB{
	meta:
		description = "Trojan:Win32/IcedId.DEO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {83 c4 04 50 6a 01 6a 00 6a 00 8d 4d f4 51 ff 15 90 01 04 85 c0 75 90 01 01 32 c0 e9 90 01 04 c7 45 d4 00 00 00 00 8d 55 d4 52 6a 00 6a 00 68 34 01 00 00 68 90 01 04 8b 45 f4 50 ff 15 90 01 04 85 c0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}