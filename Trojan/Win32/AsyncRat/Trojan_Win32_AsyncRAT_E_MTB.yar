
rule Trojan_Win32_AsyncRAT_E_MTB{
	meta:
		description = "Trojan:Win32/AsyncRAT.E!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {80 2f 88 8b 90 01 05 80 07 49 90 01 06 f6 2f 47 e2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}