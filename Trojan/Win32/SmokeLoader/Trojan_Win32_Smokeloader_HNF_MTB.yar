
rule Trojan_Win32_Smokeloader_HNF_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.HNF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {89 75 f0 81 45 f0 00 00 00 00 8b 45 f0 } //1
		$a_03_1 = {d3 ea 03 d3 8b 90 01 02 31 45 90 01 01 31 55 90 01 01 2b 7d fc 81 45 90 01 05 ff 4d 90 01 01 0f 85 90 00 } //1
		$a_03_2 = {3d a9 0f 00 00 90 02 60 83 45 90 01 01 64 29 45 90 1b 01 83 6d 90 1b 01 64 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=1
 
}