
rule Trojan_Win32_Spysnake_MX_MTB{
	meta:
		description = "Trojan:Win32/Spysnake.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {89 c8 f7 e3 d1 ea 83 e2 fc 8d 04 52 f7 d8 8a 04 07 8b 54 24 20 30 04 0a 41 47 39 ce 75 } //00 00 
	condition:
		any of ($a_*)
 
}