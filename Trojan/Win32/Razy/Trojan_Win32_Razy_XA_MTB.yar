
rule Trojan_Win32_Razy_XA_MTB{
	meta:
		description = "Trojan:Win32/Razy.XA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_02_0 = {31 08 81 ea 90 01 04 09 ff 81 c0 90 01 04 81 ef 90 01 04 01 d6 39 d8 75 df 83 ec 04 89 34 24 5a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}