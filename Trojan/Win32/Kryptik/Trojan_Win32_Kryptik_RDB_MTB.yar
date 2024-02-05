
rule Trojan_Win32_Kryptik_RDB_MTB{
	meta:
		description = "Trojan:Win32/Kryptik.RDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {8a 06 46 89 c0 32 02 47 88 47 ff 89 c0 42 52 83 c4 04 83 ec 04 c7 04 24 90 01 04 83 c4 04 49 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}