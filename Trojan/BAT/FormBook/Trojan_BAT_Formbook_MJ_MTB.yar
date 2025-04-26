
rule Trojan_BAT_Formbook_MJ_MTB{
	meta:
		description = "Trojan:BAT/Formbook.MJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 "
		
	strings :
		$a_03_0 = {02 8e 69 8d ?? ?? ?? 01 0a 16 0b 2b 1c 00 06 07 02 07 91 03 07 03 6f ?? ?? ?? 0a 5d 6f ?? ?? ?? 0a 61 d2 9c 00 07 17 58 0b 07 02 8e 69 fe 04 0c 08 2d } //5
		$a_01_1 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerBrowsableAttribute
		$a_01_2 = {49 6e 76 6f 6b 65 } //1 Invoke
		$a_01_3 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //1 MemoryStream
		$a_01_4 = {4f 62 66 75 73 63 61 74 69 6f 6e 41 74 74 72 69 62 75 74 65 } //1 ObfuscationAttribute
		$a_01_5 = {2e 00 63 00 6f 00 6d 00 70 00 72 00 65 00 73 00 73 00 65 00 64 00 } //1 .compressed
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=10
 
}