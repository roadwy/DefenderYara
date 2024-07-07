
rule Trojan_Win32_Netwire_NEAD_MTB{
	meta:
		description = "Trojan:Win32/Netwire.NEAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 "
		
	strings :
		$a_01_0 = {68 d0 07 00 00 ff d3 83 ee 01 75 f4 68 c4 09 00 00 ff d3 6a 40 68 00 10 00 00 68 a0 33 03 00 56 ff 95 f8 fe ff ff } //10
		$a_01_1 = {43 79 62 65 72 64 79 6e 65 } //2 Cyberdyne
		$a_01_2 = {58 4f 52 5f 55 6e 73 69 67 6e 65 64 5f 43 68 61 72 5f 41 72 72 61 79 5f 43 50 50 } //2 XOR_Unsigned_Char_Array_CPP
		$a_01_3 = {43 6f 6e 73 6f 6c 65 41 70 70 6c 69 63 61 74 69 6f 6e 31 2e 70 64 62 } //2 ConsoleApplication1.pdb
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=16
 
}