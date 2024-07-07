
rule Trojan_Win32_Razy_UF_MTB{
	meta:
		description = "Trojan:Win32/Razy.UF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 de 81 c3 90 01 04 31 0a 21 de 29 db 81 c2 90 01 04 4b 39 c2 75 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}