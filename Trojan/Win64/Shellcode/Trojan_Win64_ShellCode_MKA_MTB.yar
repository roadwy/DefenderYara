
rule Trojan_Win64_ShellCode_MKA_MTB{
	meta:
		description = "Trojan:Win64/ShellCode.MKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 c2 b9 fd c0 0f fc 48 0f af d1 48 c1 ea 26 89 d1 c1 e1 06 01 ca 29 d0 } //30
	condition:
		((#a_01_0  & 1)*30) >=30
 
}