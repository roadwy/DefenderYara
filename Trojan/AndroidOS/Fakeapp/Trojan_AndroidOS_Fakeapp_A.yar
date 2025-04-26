
rule Trojan_AndroidOS_Fakeapp_A{
	meta:
		description = "Trojan:AndroidOS/Fakeapp.A,SIGNATURE_TYPE_DEXHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {73 70 70 72 6f 6d 6f 2e 72 75 2f 61 70 70 73 2e 70 68 70 } //1 sppromo.ru/apps.php
	condition:
		((#a_00_0  & 1)*1) >=1
 
}