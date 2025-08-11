
rule Trojan_Win32_BypassUAC_A_MTB{
	meta:
		description = "Trojan:Win32/BypassUAC.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {49 81 d1 06 00 00 00 48 c7 44 24 00 09 f4 84 ca 48 ff 44 24 00 48 c1 74 24 00 9a 0f ad d6 68 ba 35 01 8f 41 89 31 e9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}