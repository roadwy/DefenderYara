
rule Trojan_Win32_SystemBC_psyI_MTB{
	meta:
		description = "Trojan:Win32/SystemBC.psyI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {24 14 89 44 24 08 8b 44 24 08 85 c0 75 18 8d 4c 24 04 c7 84 24 3c 01 00 00 ff ff ff ff e8 54 1f } //7
	condition:
		((#a_01_0  & 1)*7) >=7
 
}