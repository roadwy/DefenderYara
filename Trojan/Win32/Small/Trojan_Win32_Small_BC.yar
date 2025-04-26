
rule Trojan_Win32_Small_BC{
	meta:
		description = "Trojan:Win32/Small.BC,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {b8 c0 68 47 00 e8 a5 2f f9 ff 84 c0 0f 84 8c 00 00 00 b8 f0 68 47 00 e8 93 2f f9 ff 84 c0 75 7e ba c0 68 47 00 b8 ec 9f 47 00 e8 b4 d0 f8 ff b8 ec 9f 47 00 e8 46 ce f8 ff e8 71 cc f8 ff 8d 55 b8 b8 1c 69 47 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}