
rule Trojan_Win32_ICLoader_PVS_MTB{
	meta:
		description = "Trojan:Win32/ICLoader.PVS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_02_0 = {8b 7d 0c 03 7d 08 90 01 04 a1 90 01 04 03 f8 66 33 c0 8a 65 ff 80 c9 90 01 01 0c 90 01 01 30 27 61 ff 45 08 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}