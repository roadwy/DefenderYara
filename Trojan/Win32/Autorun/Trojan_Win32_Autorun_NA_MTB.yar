
rule Trojan_Win32_Autorun_NA_MTB{
	meta:
		description = "Trojan:Win32/Autorun.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {e9 0d 01 00 00 83 fb 01 0f 84 f6 00 00 00 8b 0d 24 67 40 00 89 4d 08 8b 4d 0c 89 0d 24 67 40 00 8b 48 04 83 f9 08 0f 85 c8 00 00 00 8b 0d 28 62 40 00 8b 15 2c 62 40 00 03 d1 56 3b ca 7d 15 } //2
		$a_01_1 = {89 35 34 62 40 00 59 5e eb 08 83 60 08 00 51 ff d3 59 8b 45 08 a3 24 67 40 00 83 c8 ff } //1
		$a_01_2 = {61 75 74 6f 72 75 6e 2e 69 6e 66 } //1 autorun.inf
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}