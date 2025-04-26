
rule Trojan_Win32_BHO_CJ{
	meta:
		description = "Trojan:Win32/BHO.CJ,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {f3 ab 66 ab aa 8d 85 e8 fe ff ff 50 e8 ?? ?? ?? ?? 59 8d 85 e8 fe ff ff 59 68 ?? ?? ?? ?? 56 50 e8 ?? ?? ?? ?? 59 50 8d 85 e8 fe ff ff 50 e8 ?? ?? ?? ?? 83 c4 10 8d 45 f8 50 8d 45 fc 50 53 68 3f 00 0f 00 } //1
		$a_00_1 = {62 68 6f 2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 } //1
		$a_00_2 = {4f 66 66 69 63 65 65 6c 6f 67 2e 64 6c 6c } //1 Officeelog.dll
		$a_02_3 = {43 4c 53 49 44 5c 25 73 5c 49 6e 70 72 6f 63 53 65 72 76 65 72 33 32 00 4d 69 63 72 6f 73 6f 66 74 [0-02] 28 52 29 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1) >=4
 
}