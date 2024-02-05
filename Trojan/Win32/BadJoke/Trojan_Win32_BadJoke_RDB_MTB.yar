
rule Trojan_Win32_BadJoke_RDB_MTB{
	meta:
		description = "Trojan:Win32/BadJoke.RDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {8a 0a 8b 55 ec 8a 54 15 cf 31 ca 88 10 } //00 00 
	condition:
		any of ($a_*)
 
}