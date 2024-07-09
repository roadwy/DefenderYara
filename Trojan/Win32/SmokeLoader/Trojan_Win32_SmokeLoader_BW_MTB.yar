
rule Trojan_Win32_SmokeLoader_BW_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.BW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e8 05 03 45 e8 c7 05 [0-04] 19 36 6b ff 89 45 0c 8b 45 fc 03 c6 50 8d 45 08 50 e8 [0-04] 8b 45 08 33 45 0c 68 b9 79 37 9e 2b f8 8d 45 fc 50 e8 [0-04] ff 4d f8 0f } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}