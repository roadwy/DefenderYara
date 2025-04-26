
rule Trojan_Win32_Zusy_PGY_MTB{
	meta:
		description = "Trojan:Win32/Zusy.PGY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {77 00 69 00 6e 00 73 00 76 00 63 00 2e 00 65 00 78 00 65 } //1
		$a_01_1 = {8b f9 89 7d f0 8b 75 08 33 db 89 1f 89 5f 04 89 5f 08 8b 4e 0c 89 4f 0c 8b 01 ff 50 04 89 5d fc 8b 36 85 f6 } //4
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*4) >=5
 
}