
rule Trojan_Win32_Stealerc_GPA_MTB{
	meta:
		description = "Trojan:Win32/Stealerc.GPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 84 0c 8c 00 00 00 34 bb 88 44 0c 14 41 83 f9 16 7c ed } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}