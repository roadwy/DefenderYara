
rule Trojan_Win32_Copak_RL_MTB{
	meta:
		description = "Trojan:Win32/Copak.RL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 ce 00 81 ea 4b ff c1 d3 c3 01 d7 81 c7 18 ae 63 93 00 00 81 fb f4 01 00 00 75 05 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}