
rule Trojan_Win32_Raspberryrobin_RC_MTB{
	meta:
		description = "Trojan:Win32/Raspberryrobin.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {89 c0 ac 32 02 83 ec 04 c7 04 24 90 01 04 83 c4 04 88 07 83 c7 01 56 83 c4 04 42 50 83 c4 04 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}