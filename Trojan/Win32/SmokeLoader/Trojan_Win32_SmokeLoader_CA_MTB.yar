
rule Trojan_Win32_SmokeLoader_CA_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.CA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e8 05 03 45 e8 8d 0c 37 31 4d 08 50 89 45 0c 8d 45 08 50 c7 05 [0-04] 19 36 6b ff e8 [0-04] 8b 45 08 29 45 fc 8b 45 fc 81 c7 [0-04] ff 4d f8 0f } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}