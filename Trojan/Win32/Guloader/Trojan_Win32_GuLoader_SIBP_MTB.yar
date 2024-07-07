
rule Trojan_Win32_GuLoader_SIBP_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.SIBP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {4e 75 6c 6b 6f 6d 70 6f 6e 65 6e 74 } //1 Nulkomponent
		$a_03_1 = {83 c7 04 83 34 24 90 01 01 81 ff 90 01 04 90 18 90 02 0a bb 90 01 04 90 02 0a 81 c3 90 01 04 90 02 10 81 f3 90 01 04 90 02 0a 81 c3 90 01 04 90 02 10 0b 1c 3a 90 02 0a 81 f3 90 01 04 90 02 0a 09 1c 38 90 02 0a 83 c7 04 83 34 24 90 01 01 81 ff 90 1b 01 0f 85 90 01 04 90 02 05 ff d0 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}