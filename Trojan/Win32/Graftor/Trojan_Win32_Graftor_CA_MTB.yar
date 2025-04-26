
rule Trojan_Win32_Graftor_CA_MTB{
	meta:
		description = "Trojan:Win32/Graftor.CA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 04 33 88 04 3e 83 fe ?? 75 12 8d 4d ?? 51 6a 40 68 [0-04] 57 ff 15 [0-04] 46 3b 75 fc 72 d5 } //1
		$a_03_1 = {50 6a 00 ff 15 [0-04] 81 ff c0 c6 2d 00 76 1a } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}