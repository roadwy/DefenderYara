
rule Trojan_Win32_DarkComet_MBXY_MTB{
	meta:
		description = "Trojan:Win32/DarkComet.MBXY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {84 76 41 00 0e f9 30 00 00 ff ff ff 08 00 00 00 01 } //2
		$a_01_1 = {e9 00 00 00 68 74 41 00 d4 73 41 00 68 3b 40 00 78 00 00 00 86 00 00 00 8e } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}