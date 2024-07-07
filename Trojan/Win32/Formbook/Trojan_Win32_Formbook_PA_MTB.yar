
rule Trojan_Win32_Formbook_PA_MTB{
	meta:
		description = "Trojan:Win32/Formbook.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 05 00 00 "
		
	strings :
		$a_00_0 = {33 d2 8b c1 f7 f3 8b 45 a0 41 8a 54 15 f4 30 54 01 ff 3b 4c 37 fc 72 e8 } //10
		$a_02_1 = {50 6a 00 ff 15 90 01 04 8b f8 57 6a 00 ff 15 90 01 04 57 6a 00 8b f0 ff 15 90 01 04 50 ff 15 90 00 } //10
		$a_00_2 = {4c 6f 61 64 52 65 73 6f 75 72 63 65 } //1 LoadResource
		$a_00_3 = {4c 6f 63 6b 52 65 73 6f 75 72 63 65 } //1 LockResource
		$a_00_4 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
	condition:
		((#a_00_0  & 1)*10+(#a_02_1  & 1)*10+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=23
 
}