
rule Trojan_Win32_SmokeLoader_FRP_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.FRP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 3e 50 31 50 23 50 50 50 08 d9 16 5c } //00 00 
	condition:
		any of ($a_*)
 
}