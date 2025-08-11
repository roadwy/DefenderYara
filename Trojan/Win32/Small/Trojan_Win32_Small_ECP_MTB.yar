
rule Trojan_Win32_Small_ECP_MTB{
	meta:
		description = "Trojan:Win32/Small.ECP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 0c 30 2a c8 88 0c 30 40 3b c7 } //3
		$a_02_1 = {8a 0c 30 80 c1 fc ?? ?? ?? ?? 2a d1 8a 0c 30 02 ca 88 0c 30 40 3b c7 } //3
	condition:
		((#a_01_0  & 1)*3+(#a_02_1  & 1)*3) >=6
 
}