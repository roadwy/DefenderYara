
rule Trojan_Win32_Injector_YQ_bit{
	meta:
		description = "Trojan:Win32/Injector.YQ!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 c4 0c 89 45 90 01 01 6a 0c 68 90 01 02 40 00 68 90 01 02 40 00 e8 90 01 02 ff ff 83 c4 0c 89 45 90 01 01 6a 08 68 90 01 02 40 00 68 90 01 02 40 00 e8 90 01 02 ff ff 83 c4 0c 90 00 } //01 00 
		$a_03_1 = {8b 45 08 0f be 0c 10 8b 95 90 01 02 ff ff 33 c0 8a 84 15 90 01 02 ff ff 8b 95 90 01 02 ff ff 03 d1 03 c2 25 ff 00 00 80 79 07 48 0d 00 ff ff ff 40 89 85 90 01 02 ff ff 8b 85 90 01 02 ff ff 8a 8c 05 90 01 02 ff ff 88 8d 90 01 02 ff ff 8b 95 90 01 02 ff ff 8b 85 90 01 02 ff ff 8a 8c 05 90 01 02 ff ff 88 8c 15 90 01 02 ff ff 8b 95 90 01 02 ff ff 8a 85 90 01 02 ff ff 88 84 15 90 01 02 ff ff e9 90 00 } //01 00 
		$a_01_2 = {43 75 72 72 65 6e 74 55 73 65 72 00 73 61 6e 64 00 00 00 00 76 6d 77 61 72 00 } //00 00 
	condition:
		any of ($a_*)
 
}