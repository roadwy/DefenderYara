
rule Trojan_Win32_SmkLdr_E_MTB{
	meta:
		description = "Trojan:Win32/SmkLdr.E!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {64 a1 30 00 00 00 8b f0 8a 40 02 84 c0 75 ?? 8b 46 68 83 e0 70 85 c0 75 0c 8b 46 18 8b 40 10 85 c0 } //1
		$a_00_1 = {5a eb 0c 03 ca 68 00 80 00 00 6a 00 57 ff 11 8b c6 5a 5e 5f 59 5b 5d ff e0 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}