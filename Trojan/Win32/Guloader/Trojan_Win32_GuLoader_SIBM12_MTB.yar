
rule Trojan_Win32_GuLoader_SIBM12_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.SIBM12!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {8b 0c 03 66 90 08 5a 02 81 f1 90 01 04 90 08 5a 02 89 0c 03 90 08 20 02 83 c0 04 90 08 10 02 3d 90 01 04 90 02 70 0f 85 90 01 04 90 08 b0 01 ff d3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}