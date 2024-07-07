
rule Trojan_Win32_Injector_BI_bit{
	meta:
		description = "Trojan:Win32/Injector.BI!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d0 89 95 90 01 02 ff ff db 85 90 01 02 ff ff de c1 e8 90 01 02 00 00 8b 0d 90 01 04 03 8d 90 01 02 ff ff 88 01 90 09 18 00 8b 95 90 01 02 ff ff 33 95 90 01 02 ff ff 8b 85 90 01 02 ff ff 2b 85 90 01 02 ff ff 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}