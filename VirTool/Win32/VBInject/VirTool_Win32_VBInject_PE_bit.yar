
rule VirTool_Win32_VBInject_PE_bit{
	meta:
		description = "VirTool:Win32/VBInject.PE!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 00 c6 04 24 5a c6 44 24 01 77 c6 44 24 02 53 c6 44 24 03 65 c6 44 24 04 74 c6 44 24 05 49 c6 44 24 06 6e c6 44 24 07 66 c6 44 24 08 6f c6 44 24 09 72 c6 44 24 0a 6d c6 44 24 0b 61 c6 44 24 0c 74 c6 44 24 0d 69 c6 44 24 0e 6f c6 44 24 0f 6e c6 44 24 10 50 c6 44 24 11 72 c6 44 24 12 6f c6 44 24 13 63 c6 44 24 14 65 c6 44 24 15 73 c6 44 24 16 73 89 e2 e8 ?? ?? ?? ?? 83 c4 18 6a 04 68 ?? ?? ?? ?? 6a 22 6a ff ff d0 ff e7 31 34 0f c3 } //1
		$a_01_1 = {ad 83 f8 00 74 fa 81 38 55 8b ec 83 75 f2 81 78 04 ec 0c 56 8d 75 e9 31 db 53 53 53 54 68 00 00 05 00 52 51 54 ff d0 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}