
rule TrojanSpy_Win32_Bancos_RE{
	meta:
		description = "TrojanSpy:Win32/Bancos.RE,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_00_0 = {61 00 6d 00 6f 00 72 00 5f 00 69 00 6e 00 61 00 62 00 61 00 6c 00 61 00 76 00 65 00 6c 00 2e 00 73 00 77 00 66 00 00 00 } //1
		$a_00_1 = {5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 62 00 72 00 61 00 64 00 65 00 73 00 2e 00 65 00 78 00 65 00 00 00 } //1
		$a_02_2 = {c7 85 78 ff ff ff 08 00 00 00 8d 85 74 ff ff ff 50 8d 4d a8 51 8d 95 78 ff ff ff 52 8d 45 98 50 ff 15 ?? ?? ?? ?? 50 8d 4d cc 51 ff 15 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? 8b 55 08 8b 02 8b 4d 08 51 ff 90 90 f8 06 00 00 } //2
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*2) >=4
 
}