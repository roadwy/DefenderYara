
rule Trojan_Win32_Remcos_GVC_MTB{
	meta:
		description = "Trojan:Win32/Remcos.GVC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {30 84 0a 17 00 00 00 02 84 0a 17 00 00 00 e2 f0 } //3
		$a_01_1 = {30 94 0e 17 00 00 00 02 94 0e 17 00 00 00 e2 f0 } //3
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3) >=3
 
}