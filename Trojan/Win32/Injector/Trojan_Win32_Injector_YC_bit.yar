
rule Trojan_Win32_Injector_YC_bit{
	meta:
		description = "Trojan:Win32/Injector.YC!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 f1 0f be 92 90 01 04 8b 45 08 03 45 90 01 01 0f b6 08 33 ca 8b 55 08 03 55 90 01 01 88 0a e8 90 01 04 8b 4d 08 03 4d 90 01 01 0f b6 11 33 d0 8b 45 08 03 45 90 01 01 88 10 8b 4d 08 03 4d 90 01 01 8b 55 08 03 55 90 01 01 8a 02 88 01 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}