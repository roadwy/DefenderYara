
rule Trojan_Win32_Cridex_DEQ_MTB{
	meta:
		description = "Trojan:Win32/Cridex.DEQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {b9 01 00 00 00 c1 e1 02 0f b6 91 90 01 04 b8 01 00 00 00 c1 e0 03 0f b6 88 90 01 04 2b d1 81 fa 90 01 04 90 13 8b 4d e8 83 e9 03 8b 75 ec 83 de 00 0f b7 45 fc 99 2b c8 1b f2 ba 01 00 00 00 6b c2 0c 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}