
rule Trojan_Win32_Injector_YO_bit{
	meta:
		description = "Trojan:Win32/Injector.YO!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {41 40 83 f8 90 01 01 7c dd 90 09 1c 00 8a 90 90 90 01 04 32 d1 41 81 e1 ff 00 00 80 88 54 04 14 79 08 49 81 c9 00 ff ff ff 90 00 } //1
		$a_03_1 = {8b d1 81 e2 90 01 04 79 05 4a 83 90 01 02 42 f7 da 1a d2 bf 90 01 04 80 e2 90 01 01 fe c2 8a c2 f6 e9 8a d8 8b c1 99 f7 ff 8a 82 90 01 04 2a d8 8a 04 31 02 c3 88 04 31 8b 90 01 03 41 3b c8 7c bf 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}