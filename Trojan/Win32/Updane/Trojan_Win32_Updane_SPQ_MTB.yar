
rule Trojan_Win32_Updane_SPQ_MTB{
	meta:
		description = "Trojan:Win32/Updane.SPQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 c1 87 d9 b9 a3 ff ff ff 29 cb 8b 7b a3 8b cf 87 d9 b9 ff ff ff ff 31 cb 81 e3 90 01 04 81 e7 90 01 04 0b fb 89 3e b9 90 01 04 81 f1 90 01 04 01 ce c7 c3 90 01 04 c7 c7 90 01 04 31 df 01 f8 68 90 01 04 bf 90 01 04 5b 33 fb bb 90 01 04 31 df 33 f8 81 cf 00 00 00 00 0f 85 98 ff ff ff 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}