
rule Trojan_Win32_PonyStealer_PD_MTB{
	meta:
		description = "Trojan:Win32/PonyStealer.PD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {85 c0 46 66 85 db ff 37 85 ff 90 02 6f 59 90 02 10 31 f1 90 02 10 39 c1 75 90 00 } //01 00 
		$a_02_1 = {85 ff 46 81 fb 90 01 04 ff 37 66 90 01 04 59 90 02 10 31 f1 90 02 10 39 c1 0f 85 90 01 02 ff ff 90 00 } //01 00 
		$a_02_2 = {66 85 db 46 81 fb 90 01 04 ff 37 90 02 bf 59 90 02 10 31 f1 90 02 10 39 c1 0f 85 90 01 02 ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}