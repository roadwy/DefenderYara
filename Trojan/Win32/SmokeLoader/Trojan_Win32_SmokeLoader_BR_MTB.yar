
rule Trojan_Win32_SmokeLoader_BR_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.BR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b f0 8b 45 fc 8d 14 30 8b c6 c1 e8 05 89 45 08 8d 45 08 50 c7 05 90 02 04 19 36 6b ff e8 90 02 04 83 65 0c 00 8b c6 c1 e0 04 03 45 e4 33 45 08 33 c2 2b f8 8b 45 e0 01 45 0c 29 45 fc ff 4d f4 0f 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}