
rule Trojan_Win32_IcedId_SIBJ3_MTB{
	meta:
		description = "Trojan:Win32/IcedId.SIBJ3!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {4f 69 6c 2e 64 6c 6c } //01 00 
		$a_03_1 = {83 c0 04 89 90 02 0a 89 44 24 90 01 01 3d 90 01 04 73 90 01 01 90 02 0a 90 18 90 02 3a 03 2d 90 01 04 90 02 10 8b 85 90 01 04 89 44 24 90 01 01 90 02 55 8b 44 24 90 1b 0a 05 90 01 04 90 02 0a 89 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}