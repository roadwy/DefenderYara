
rule Trojan_Win32_Injector_BI_bit{
	meta:
		description = "Trojan:Win32/Injector.BI!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d0 89 95 ?? ?? ff ff db 85 ?? ?? ff ff de c1 e8 ?? ?? 00 00 8b 0d ?? ?? ?? ?? 03 8d ?? ?? ff ff 88 01 90 09 18 00 8b 95 ?? ?? ff ff 33 95 ?? ?? ff ff 8b 85 ?? ?? ff ff 2b 85 ?? ?? ff ff } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}