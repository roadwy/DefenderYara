
rule Trojan_Win32_SmokeLoader_XII_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.XII!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 e8 03 c5 81 3d 90 01 08 89 44 24 90 01 01 75 90 01 01 57 57 57 57 ff 15 90 01 04 8b 44 24 90 01 01 31 44 24 90 01 01 8b 44 24 90 01 01 29 44 24 90 01 01 8d 44 24 90 01 01 e8 90 01 04 83 6c 24 90 01 02 0f 85 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}