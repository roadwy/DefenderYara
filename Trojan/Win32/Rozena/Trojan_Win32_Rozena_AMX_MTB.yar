
rule Trojan_Win32_Rozena_AMX_MTB{
	meta:
		description = "Trojan:Win32/Rozena.AMX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 c8 f7 ea 89 d0 c1 f8 05 89 ca c1 fa 1f 29 d0 69 d0 2c 01 00 00 89 c8 29 d0 89 06 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}