
rule Trojan_Win32_Emotet_E{
	meta:
		description = "Trojan:Win32/Emotet.E,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {89 1d 24 4d 47 00 a3 14 4d 47 00 55 a3 18 4d 47 00 a1 5c 4e 47 00 54 8b 00 89 1d 1c 4d 47 00 8f 05 24 4d 47 00 8b 00 83 05 24 4d 47 00 04 8f 05 20 4d 47 00 50 89 35 14 4d 47 00 89 3d 18 4d 47 00 ff e0 } //1
		$a_01_1 = {79 00 3a 00 5c 00 6a 00 6f 00 62 00 5c 00 74 00 65 00 6d 00 70 00 30 00 33 00 32 00 39 00 31 00 2e 00 64 00 6f 00 63 00 } //1 y:\job\temp03291.doc
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}