
rule Trojan_Win32_Coroxy_GPC_MTB{
	meta:
		description = "Trojan:Win32/Coroxy.GPC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_01_0 = {46 8a 04 3b 30 06 7a 04 7b 02 61 14 46 43 49 3b 5d 0c } //00 00 
	condition:
		any of ($a_*)
 
}