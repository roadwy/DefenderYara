
rule Trojan_Win32_Injector_MKZ_MTB{
	meta:
		description = "Trojan:Win32/Injector.MKZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c8 8b 45 f8 33 d2 f7 f1 52 8b 4d 08 e8 ?? ?? ?? ?? 0f be 10 8b 85 30 ff ff ff 0f be 08 33 ca 8b 95 30 ff ff ff 88 0a eb } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}