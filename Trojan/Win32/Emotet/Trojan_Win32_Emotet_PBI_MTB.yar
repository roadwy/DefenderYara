
rule Trojan_Win32_Emotet_PBI_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PBI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {8a 04 0f 81 e2 ff 00 00 00 03 c2 33 d2 f7 35 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 00 8a 14 0a 32 14 18 a1 ?? ?? ?? ?? 8b 5c 24 ?? 8b 00 88 14 18 } //1
		$a_81_1 = {4f 41 50 33 6f 6d 6e 57 4d 69 65 70 53 76 77 61 4d 5a 2a 4c 51 70 5a 5a 71 7e 4a 42 4d 43 73 25 4b 68 38 6e 6a 48 73 37 61 4d 42 7e 54 64 6e 58 45 53 4a 34 78 25 25 57 63 58 2a 41 5a 33 4c 55 56 6c 61 59 72 4a 65 7e 78 25 6f 73 35 43 59 63 57 4d 6c } //1 OAP3omnWMiepSvwaMZ*LQpZZq~JBMCs%Kh8njHs7aMB~TdnXESJ4x%%WcX*AZ3LUVlaYrJe~x%os5CYcWMl
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}