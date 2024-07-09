
rule Trojan_Win32_Injector_YC_bit{
	meta:
		description = "Trojan:Win32/Injector.YC!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 f1 0f be 92 ?? ?? ?? ?? 8b 45 08 03 45 ?? 0f b6 08 33 ca 8b 55 08 03 55 ?? 88 0a e8 ?? ?? ?? ?? 8b 4d 08 03 4d ?? 0f b6 11 33 d0 8b 45 08 03 45 ?? 88 10 8b 4d 08 03 4d ?? 8b 55 08 03 55 ?? 8a 02 88 01 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}