
rule Trojan_Win32_BHO_DE{
	meta:
		description = "Trojan:Win32/BHO.DE,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_02_0 = {ff d6 3b c3 0f 85 90 01 04 6a 13 33 c0 5a 8d bd 6d fe ff ff 8b ca 88 9d 6c fe ff ff f3 ab 66 ab aa 90 00 } //1
		$a_00_1 = {43 4c 53 49 44 20 3d 20 73 20 27 7b 36 37 45 34 44 44 38 46 2d 46 38 39 39 2d 34 62 39 39 2d 41 35 42 32 2d 43 37 32 34 34 35 42 35 43 39 36 32 7d 27 } //1 CLSID = s '{67E4DD8F-F899-4b99-A5B2-C72445B5C962}'
		$a_00_2 = {49 45 48 70 72 2e 49 6e 76 6f 6b 65 2e 31 20 3d 20 73 20 27 42 48 4f 20 43 6c 61 73 73 27 } //1 IEHpr.Invoke.1 = s 'BHO Class'
		$a_00_3 = {54 6f 6f 6c 62 61 72 57 69 6e 64 6f 77 33 32 00 49 45 46 72 61 6d 65 00 } //1 潔汯慢坲湩潤㍷2䕉牆浡e
		$a_00_4 = {46 00 6c 00 61 00 63 00 64 00 6b 00 65 00 72 00 } //1 Flacdker
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}