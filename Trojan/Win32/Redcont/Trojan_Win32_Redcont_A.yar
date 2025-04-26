
rule Trojan_Win32_Redcont_A{
	meta:
		description = "Trojan:Win32/Redcont.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {6a 01 6a 00 6a 00 6a 00 53 e8 ?? ?? ?? ?? 85 c0 74 e7 83 7b 04 12 0f 84 } //1
		$a_03_1 = {41 70 70 46 69 6c [0-02] 51 73 53 53 53 77 77 77 77 } //1
		$a_01_2 = {4d 6c 6a 6b 66 62 6c 67 6a 6e 73 6c 73 64 66 6e 67 6b 6a 73 64 6e 66 67 6c 6b } //1 Mljkfblgjnslsdfngkjsdnfglk
		$a_03_3 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 62 6f [0-01] 74 6d 67 72 2e 69 6e 69 } //1
		$a_03_4 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 64 65 6c [0-01] 2e 74 78 74 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}