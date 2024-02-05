
rule Trojan_Win32_Coroxy_MR_MTB{
	meta:
		description = "Trojan:Win32/Coroxy.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 4c 24 0c 30 90 02 02 81 fb 90 02 04 90 18 47 3b fb 90 18 81 fb 90 02 04 90 18 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}