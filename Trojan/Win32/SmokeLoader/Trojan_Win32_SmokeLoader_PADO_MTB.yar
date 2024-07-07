
rule Trojan_Win32_SmokeLoader_PADO_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.PADO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {51 c7 04 24 f0 43 03 00 83 04 24 0d a1 90 01 04 0f af 04 24 05 c3 9e 26 00 a3 90 01 04 0f b7 05 90 01 04 25 ff 7f 00 00 59 c3 90 00 } //1
		$a_03_1 = {7e 20 55 8b 2d 90 01 04 8b ff e8 8b ff ff ff 30 04 1e 83 ff 0f 75 04 6a 00 ff d5 46 3b f7 7c ea 5d 5e 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}