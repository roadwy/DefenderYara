
rule Trojan_Win32_Stealerc_AMBA_MTB{
	meta:
		description = "Trojan:Win32/Stealerc.AMBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {89 45 f4 b8 90 01 04 8b 5d f4 b9 90 01 04 35 90 01 04 25 90 01 04 0d 90 01 04 89 03 01 cb 35 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}