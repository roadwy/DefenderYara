
rule Trojan_Win32_Phorpiex_J_MTB{
	meta:
		description = "Trojan:Win32/Phorpiex.J!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a c8 8a d0 24 f0 80 e1 fc 02 c0 c0 e1 04 0a 4f 01 02 c0 0a 07 c0 e2 06 0a 57 02 88 04 1e 88 4c 1e 01 8b 4c 24 18 88 54 1e 02 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}