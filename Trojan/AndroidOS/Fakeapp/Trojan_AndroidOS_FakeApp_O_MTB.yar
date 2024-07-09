
rule Trojan_AndroidOS_FakeApp_O_MTB{
	meta:
		description = "Trojan:AndroidOS/FakeApp.O!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {3b 00 08 00 22 00 ?? ?? ?? ?? ?? 46 50 00 11 00 d8 06 02 ff 6e 20 ?? 46 28 00 0a 00 6e 20 ?? 46 34 00 0a 07 b7 70 df 00 00 ?? 8e 00 50 00 05 02 3a 06 ea ff 6e 20 ?? 46 68 00 0a 00 6e 20 ?? 46 34 00 0a 02 b7 20 df 00 00 ?? 8e 07 d8 02 06 ff d8 00 03 ff 50 07 05 06 3b 00 03 00 01 10 01 03 01 20 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}