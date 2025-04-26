
rule Trojan_Win64_CryptInject_PIN_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.PIN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 f6 89 95 50 ff ff ff 2b 75 af 89 8d 51 ff ff ff 89 d6 01 75 cb 48 89 95 9a fe ff ff 89 c9 8b bd ce fe ff ff 66 8b 55 d7 48 31 b5 ?? ?? ff ff 0f b6 c4 4d 31 f8 48 ff 04 24 be 05 00 00 00 3b 34 24 0f 8c } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}