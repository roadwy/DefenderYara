
rule Trojan_Win32_Injector_YB_bit{
	meta:
		description = "Trojan:Win32/Injector.YB!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 08 03 85 90 01 02 ff ff 8a 00 32 84 95 f4 fb ff ff 8b 4d 08 03 8d 90 01 02 ff ff 88 01 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}