
rule Trojan_Win32_Delf_GL_bit{
	meta:
		description = "Trojan:Win32/Delf.GL!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {2f 63 20 70 69 6e 67 20 31 32 37 2e 30 2e 30 2e 31 00 00 00 ff ff ff ff 07 00 00 00 63 6d 64 2e 65 78 65 00 } //1
		$a_01_1 = {6d 65 67 61 70 65 73 74 72 00 00 00 ff ff ff ff 09 00 00 00 6d 65 67 61 70 65 65 6e 64 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}