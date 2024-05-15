
rule Trojan_Win32_Zenpak_SPDB_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.SPDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {83 ec 0c 83 65 fc 00 89 55 f4 89 4d f8 8b 45 f4 01 45 fc 8b 45 fc 31 45 f8 8b 45 f8 } //00 00 
	condition:
		any of ($a_*)
 
}