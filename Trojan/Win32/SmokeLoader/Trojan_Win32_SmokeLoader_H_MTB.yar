
rule Trojan_Win32_SmokeLoader_H_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.H!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {33 cf 31 4c 24 90 01 01 8b 44 24 90 01 01 29 44 24 90 01 01 8b 15 90 01 04 81 fa 90 01 04 74 90 01 01 8d 44 24 90 00 } //02 00 
		$a_01_1 = {33 c7 33 c1 2b f0 8b ce c1 e1 } //00 00 
	condition:
		any of ($a_*)
 
}