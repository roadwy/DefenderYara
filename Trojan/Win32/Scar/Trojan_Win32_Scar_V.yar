
rule Trojan_Win32_Scar_V{
	meta:
		description = "Trojan:Win32/Scar.V,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 64 6c 65 78 65 63 00 73 6f 63 6b 73 35 00 } //1
		$a_03_1 = {c7 04 24 e0 93 04 00 b8 22 00 00 00 89 85 90 01 02 ff ff e8 90 01 04 ff 85 90 01 02 ff ff 83 ec 04 e9 90 01 02 ff ff 83 c5 18 8b 85 90 01 02 ff ff 8b 95 90 01 02 ff ff 83 f8 01 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}