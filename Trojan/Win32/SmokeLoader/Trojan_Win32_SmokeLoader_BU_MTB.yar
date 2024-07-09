
rule Trojan_Win32_SmokeLoader_BU_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.BU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 45 ec 8b 45 ec 89 45 e4 8b 4d f0 8b c3 d3 e8 03 45 c8 89 45 f8 8b 45 e4 31 45 fc 8b 45 f8 31 45 fc 89 35 [0-04] 8b 45 fc 29 45 f4 8d 45 e0 e8 [0-04] ff 4d dc 0f } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}