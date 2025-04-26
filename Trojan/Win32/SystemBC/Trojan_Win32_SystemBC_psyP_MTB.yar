
rule Trojan_Win32_SystemBC_psyP_MTB{
	meta:
		description = "Trojan:Win32/SystemBC.psyP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_03_0 = {57 ff 75 08 ff 75 fc 57 e8 61 78 ff ff 50 6a ?? ff 15 48 81 41 00 50 89 86 94 } //7
	condition:
		((#a_03_0  & 1)*7) >=7
 
}