
rule Trojan_Win32_MysticStealer_ASAX_MTB{
	meta:
		description = "Trojan:Win32/MysticStealer.ASAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {ff d6 80 34 2f ?? ff d6 80 04 2f ?? ff d6 80 04 2f ?? ff d6 80 04 2f ?? 47 3b fb 0f 82 } //5
		$a_03_1 = {ff d6 80 34 ?? fc ff d6 fe 04 2f ff d6 80 04 2f ?? ff d6 80 04 2f ?? 47 3b fb 0f 82 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=5
 
}