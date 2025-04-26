
rule Trojan_Win32_SmokeLoader_BY_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.BY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b f8 89 45 0c 8b c7 c1 e0 04 89 7d e8 89 45 08 8b 45 e4 01 45 08 8b 45 e8 03 45 f8 89 45 fc 83 0d [0-04] ff 8b c7 c1 e8 05 03 45 e0 68 b9 79 37 9e 33 45 fc c7 05 [0-04] 19 36 6b ff 31 45 08 2b 75 08 8d 45 f8 50 e8 [0-04] ff 4d f4 0f } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}