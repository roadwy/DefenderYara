
rule Trojan_Win32_Zenpak_SPHD_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.SPHD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {69 67 6b 63 42 6f 47 31 79 4a 34 51 57 78 7a 4f 61 72 55 7c 73 73 32 6f 75 58 48 6d 4c 2b } //2 igkcBoG1yJ4QWxzOarU|ss2ouXHmL+
		$a_01_1 = {4e 72 69 62 75 74 74 65 74 61 61 74 6f 54 64 68 74 69 } //2 NributtetaatoTdhti
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}