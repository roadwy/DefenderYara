
rule Trojan_Win32_SmokeLoader_BV_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.BV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 45 f0 8b 45 f0 89 45 e8 8b 4d f4 8b c7 d3 e8 03 45 c8 89 45 f8 8b 45 e8 31 45 fc 8b 45 fc 33 45 f8 89 1d [0-04] 29 45 e0 89 45 fc 8d 45 e4 e8 [0-04] ff 4d dc 0f } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}