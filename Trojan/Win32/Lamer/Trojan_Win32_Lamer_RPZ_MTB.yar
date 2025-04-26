
rule Trojan_Win32_Lamer_RPZ_MTB{
	meta:
		description = "Trojan:Win32/Lamer.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {b9 40 00 00 00 33 c0 8d 7c 24 0d c6 44 24 0c 00 f3 ab 66 ab aa 8b fd 83 c9 ff 33 c0 8d 54 24 0c f2 ae f7 d1 2b f9 8b f7 8b fa 8b d1 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}