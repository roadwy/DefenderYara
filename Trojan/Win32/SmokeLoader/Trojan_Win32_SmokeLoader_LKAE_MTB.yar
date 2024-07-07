
rule Trojan_Win32_SmokeLoader_LKAE_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.LKAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {81 3d 54 40 8f 01 90 01 02 00 00 a1 b8 4a 8f 01 8a 84 18 4b 13 01 00 8b 0d 74 5d 8d 01 88 04 19 75 90 00 } //1
		$a_03_1 = {6a 40 68 00 10 00 00 ff 35 90 01 04 6a 00 ff 15 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}