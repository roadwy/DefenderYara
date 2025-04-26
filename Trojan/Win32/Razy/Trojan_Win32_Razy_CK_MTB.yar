
rule Trojan_Win32_Razy_CK_MTB{
	meta:
		description = "Trojan:Win32/Razy.CK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {39 c0 74 01 ea 31 0a 81 c2 04 00 00 00 39 c2 75 ef } //2
		$a_01_1 = {42 09 df 4b 81 eb 19 ec 0b 91 81 fa cf 50 00 01 75 c1 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=2
 
}