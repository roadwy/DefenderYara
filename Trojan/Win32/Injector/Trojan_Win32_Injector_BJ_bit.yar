
rule Trojan_Win32_Injector_BJ_bit{
	meta:
		description = "Trojan:Win32/Injector.BJ!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 ca 83 f1 90 01 01 8b 90 01 02 6b c0 90 01 01 99 be 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}