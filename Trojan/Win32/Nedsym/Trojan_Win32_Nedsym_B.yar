
rule Trojan_Win32_Nedsym_B{
	meta:
		description = "Trojan:Win32/Nedsym.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_03_0 = {ff 57 0c ff b5 44 ff ff ff 68 ?? ?? 43 00 ff 75 e4 68 ?? ?? 43 00 8d 45 dc ba 05 00 00 00 e8 ?? ?? fc ff 43 ff 4d c4 0f 85 ?? fd ff ff } //4
		$a_01_1 = {73 79 73 72 65 67 00 00 ff ff ff ff 07 00 00 00 53 75 6d 6d 61 72 79 00 } //2
		$a_01_2 = {43 68 6f 6f 73 69 6e 67 20 52 65 73 70 6f 6e 63 65 73 2e 2e 2e 2e 00 } //1
		$a_01_3 = {2f 73 74 61 74 31 2e 70 68 70 00 } //1
		$a_01_4 = {2f 75 2e 70 68 70 3f 00 } //1 甯瀮灨?
		$a_01_5 = {68 64 70 6f 72 74 2e 73 79 73 00 } //1
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=4
 
}