
rule Trojan_Win32_Razy_D_MTB{
	meta:
		description = "Trojan:Win32/Razy.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {29 cf 81 ef 90 01 04 31 10 09 c9 40 4f 81 ef 90 01 04 39 d8 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}