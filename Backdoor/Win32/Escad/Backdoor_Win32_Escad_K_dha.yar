
rule Backdoor_Win32_Escad_K_dha{
	meta:
		description = "Backdoor:Win32/Escad.K!dha,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {25 73 6d 64 2e 65 25 73 63 20 22 25 73 20 3e 20 25 73 22 } //1 %smd.e%sc "%s > %s"
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Backdoor_Win32_Escad_K_dha_2{
	meta:
		description = "Backdoor:Win32/Escad.K!dha,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {25 73 6d 64 2e 65 25 73 63 20 22 25 73 20 3e 20 25 73 22 } //1 %smd.e%sc "%s > %s"
	condition:
		((#a_01_0  & 1)*1) >=1
 
}