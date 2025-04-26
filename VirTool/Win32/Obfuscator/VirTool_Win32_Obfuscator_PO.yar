
rule VirTool_Win32_Obfuscator_PO{
	meta:
		description = "VirTool:Win32/Obfuscator.PO,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 02 00 03 00 00 "
		
	strings :
		$a_13_0 = {00 10 00 00 53 ff 95 90 01 02 ff ff 0b c0 75 90 14 0b c0 74 0c 81 fb 00 00 00 90 01 01 0f 82 90 01 02 ff ff 90 00 01 } //1
		$a_0f_1 = {b7 03 2d 4d 5a 00 00 0b c0 75 90 01 01 81 7b 3c 00 10 00 } //8448
		$a_01_2 = {01 03 5b 3c 8b 43 08 90 00 02 00 9b 12 ff ff 57 8d 00 c6 85 90 01 02 ff ff 49 8d 00 c6 85 90 01 02 ff ff 4e 8d 00 c6 85 90 01 02 ff ff 53 8d 00 c6 85 90 01 02 ff ff 50 8d 00 c6 85 90 01 02 ff ff 4f 8d 00 c6 85 90 01 02 ff ff 4f 8d 00 c6 85 90 01 02 ff ff 4c 8d 00 c6 85 90 01 02 ff ff 2e 8d 00 c6 85 90 01 02 ff ff 44 8d 00 c6 85 90 01 02 ff ff 52 8d 00 c6 85 90 01 02 ff ff 56 8d 00 c6 85 90 01 02 ff ff 00 8d 85 90 01 02 ff ff 50 } //30464
	condition:
		((#a_13_0  & 1)*1+(#a_0f_1  & 1)*8448+(#a_01_2  & 1)*30464) >=2
 
}