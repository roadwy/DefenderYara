
rule Trojan_Win32_MysticStealer_MBJH_MTB{
	meta:
		description = "Trojan:Win32/MysticStealer.MBJH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff d6 80 04 2f ?? ff d6 80 34 2f ?? ff d6 ff d6 80 04 2f ?? ff d6 80 04 2f ?? 47 3b fb 0f 82 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}