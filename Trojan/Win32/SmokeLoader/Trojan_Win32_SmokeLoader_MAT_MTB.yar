
rule Trojan_Win32_SmokeLoader_MAT_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.MAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {30 0c 30 83 ff 0f 75 90 0a 1b 00 81 05 90 01 04 c3 9e 26 00 8a 0d 9a 90 01 03 8b 44 24 0c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}