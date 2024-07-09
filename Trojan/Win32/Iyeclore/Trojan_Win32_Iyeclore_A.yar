
rule Trojan_Win32_Iyeclore_A{
	meta:
		description = "Trojan:Win32/Iyeclore.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {83 f8 06 76 05 e8 ?? ?? ?? ff 40 8b 04 85 ?? ?? ?? ?? 89 45 c0 c6 45 c4 0b 0f b7 45 f6 89 45 c8 c6 45 cc 00 0f b7 45 f4 48 83 f8 0b 76 05 } //1
		$a_01_1 = {44 52 56 00 64 42 61 74 32 00 } //1 剄V䉤瑡2
		$a_01_2 = {53 79 73 74 65 6d 52 65 67 69 73 74 65 72 00 } //1
		$a_01_3 = {66 72 6d 5f 49 45 78 70 6c 63 72 65 4d 61 69 6e } //1 frm_IExplcreMain
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}