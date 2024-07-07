
rule Trojan_Win32_MysticStealer_ASAX_MTB{
	meta:
		description = "Trojan:Win32/MysticStealer.ASAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {ff d6 80 34 2f 90 01 01 ff d6 80 04 2f 90 01 01 ff d6 80 04 2f 90 01 01 ff d6 80 04 2f 90 01 01 47 3b fb 0f 82 90 00 } //5
		$a_03_1 = {ff d6 80 34 90 01 01 fc ff d6 fe 04 2f ff d6 80 04 2f 90 01 01 ff d6 80 04 2f 90 01 01 47 3b fb 0f 82 90 00 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=5
 
}