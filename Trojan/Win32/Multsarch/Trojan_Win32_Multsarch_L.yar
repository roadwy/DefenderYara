
rule Trojan_Win32_Multsarch_L{
	meta:
		description = "Trojan:Win32/Multsarch.L,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 d2 81 c2 05 f4 ff ff 83 c2 03 83 ea f9 52 68 83 d0 91 00 50 e8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}