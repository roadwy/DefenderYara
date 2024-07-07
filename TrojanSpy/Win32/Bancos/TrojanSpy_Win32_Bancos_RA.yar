
rule TrojanSpy_Win32_Bancos_RA{
	meta:
		description = "TrojanSpy:Win32/Bancos.RA,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {8a 54 11 ff 0f b7 ce c1 e9 07 6b c9 82 80 c1 5a 32 d1 } //2
		$a_01_1 = {ef c9 cf db c8 d3 d5 9a 94 } //1
		$a_01_2 = {fe db ce db 9a 94 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}