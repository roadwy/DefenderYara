
rule Trojan_Win32_Apolmy_B{
	meta:
		description = "Trojan:Win32/Apolmy.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {89 1d 03 00 00 00 c6 05 11 00 00 00 04 c7 05 5b 00 00 00 } //2
		$a_01_1 = {b8 fb ff ff ff } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}