
rule Trojan_Win32_Luca_ALU_MTB{
	meta:
		description = "Trojan:Win32/Luca.ALU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {f7 e2 0f af de 01 d3 ba cd cc cc cc 0f af fa 01 df 41 ba 33 33 33 33 39 c2 19 fa 89 c3 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}