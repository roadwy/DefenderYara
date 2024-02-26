
rule Trojan_Win32_SmokeLoader_AM_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {88 14 01 8b cb ff 46 90 01 01 8b 56 90 01 01 8b 46 90 01 01 c1 e9 08 88 0c 02 ff 46 90 01 01 8b 4e 90 01 01 a1 90 01 04 88 1c 08 ff 05 90 01 04 81 fd 90 01 04 0f 8c 90 01 02 ff ff 90 00 } //01 00 
		$a_03_1 = {8b 46 0c 03 86 90 01 04 35 90 01 04 0f af 05 90 01 04 6a 90 01 01 a3 90 01 04 a1 90 01 04 8b 80 90 01 04 33 05 90 01 04 83 f0 90 01 01 09 86 90 01 04 a1 90 01 04 8b 48 90 01 01 8b 86 90 01 04 81 c1 90 01 04 03 c1 31 86 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}