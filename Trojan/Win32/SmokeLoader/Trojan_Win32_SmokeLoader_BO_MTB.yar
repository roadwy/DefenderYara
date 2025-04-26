
rule Trojan_Win32_SmokeLoader_BO_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.BO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 e0 8b 4d f0 03 45 d4 89 45 f8 8b 45 e8 03 c6 89 45 f4 8b c6 d3 e8 03 45 d0 89 45 fc 8b 45 f4 31 45 f8 8b 45 f8 33 45 fc 83 25 [0-04] 00 81 45 e8 47 86 c8 61 2b d8 ff 4d e0 89 45 f8 89 5d e4 0f } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}