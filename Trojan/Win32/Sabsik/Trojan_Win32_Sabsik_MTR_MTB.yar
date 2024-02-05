
rule Trojan_Win32_Sabsik_MTR_MTB{
	meta:
		description = "Trojan:Win32/Sabsik.MTR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {83 c3 00 83 c3 00 83 c4 0a 83 ec 0a 83 c3 00 83 c3 00 8a 08 02 ca 32 ca 02 ca 32 ca 88 08 40 4e } //00 00 
	condition:
		any of ($a_*)
 
}