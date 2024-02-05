
rule Trojan_Win32_Emotet_X{
	meta:
		description = "Trojan:Win32/Emotet.X,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {e8 ad ff ff ff 83 f9 02 89 45 fc 74 10 81 fc 1f 01 00 00 e8 9a ff ff ff e8 90 01 02 ff ff 31 c0 c3 90 00 } //01 00 
		$a_03_1 = {e8 ad ff ff ff 83 f9 02 89 45 fc 74 10 81 fc 1f 01 00 00 e8 9a ff ff ff e8 90 01 02 ff ff 31 c0 c3 31 c0 31 c0 89 45 f8 55 89 e5 90 00 } //01 00 
		$a_00_2 = {4d 00 75 00 73 00 69 00 63 00 6d 00 61 00 74 00 63 00 68 00 ae 00 2c 00 20 00 49 00 6e 00 63 00 } //00 00 
	condition:
		any of ($a_*)
 
}