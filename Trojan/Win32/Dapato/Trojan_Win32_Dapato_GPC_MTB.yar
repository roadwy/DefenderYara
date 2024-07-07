
rule Trojan_Win32_Dapato_GPC_MTB{
	meta:
		description = "Trojan:Win32/Dapato.GPC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 02 00 00 "
		
	strings :
		$a_01_0 = {6d 00 6f 00 6e 00 65 00 79 00 6d 00 6f 00 74 00 69 00 76 00 65 00 73 00 2e 00 63 00 63 } //4
		$a_01_1 = {6c 00 6d 00 61 00 6f 00 2e 00 65 00 78 00 65 } //4
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*4) >=8
 
}