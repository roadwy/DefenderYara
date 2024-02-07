
rule VirTool_Win32_VBInject_EK{
	meta:
		description = "VirTool:Win32/VBInject.EK,SIGNATURE_TYPE_PEHSTR_EXT,09 00 05 00 05 00 00 03 00 "
		
	strings :
		$a_00_0 = {43 00 72 00 79 00 70 00 74 00 33 00 72 00 5c 00 64 00 65 00 6d 00 6f 00 6e 00 69 00 6f 00 36 00 36 00 36 00 76 00 69 00 70 00 2e 00 76 00 62 00 70 00 } //02 00  Crypt3r\demonio666vip.vbp
		$a_01_1 = {63 6c 73 54 77 6f 66 69 73 68 } //01 00  clsTwofish
		$a_01_2 = {52 74 6c 4d 6f 76 65 4d 65 6d 6f 72 79 } //01 00  RtlMoveMemory
		$a_01_3 = {45 6e 63 72 79 70 74 42 79 74 65 } //02 00  EncryptByte
		$a_00_4 = {49 00 6e 00 64 00 65 00 74 00 65 00 63 00 74 00 61 00 62 00 6c 00 65 00 73 00 2e 00 6e 00 65 00 74 00 } //00 00  Indetectables.net
	condition:
		any of ($a_*)
 
}