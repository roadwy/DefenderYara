
rule Trojan_Win32_Dlass_GPPB_MTB{
	meta:
		description = "Trojan:Win32/Dlass.GPPB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {4a e6 0c 00 36 e6 0c 00 26 e6 0c 00 16 e6 0c 00 08 e6 0c 00 f8 e5 0c 00 e6 e5 0c 00 d6 e5 0c 00 c6 e5 0c 00 b4 e5 0c 00 a6 e5 0c 00 5c e6 0c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}