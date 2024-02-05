
rule Trojan_Win32_Cryptinject_MTB{
	meta:
		description = "Trojan:Win32/Cryptinject!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8d 41 01 b9 90 01 04 99 f7 f9 8b ca 8b 84 8d 90 01 04 03 c3 bb 90 01 04 99 f7 fb 8b da 8a 84 8d 90 01 04 8b 94 9d 90 01 04 89 94 8d 90 01 04 25 90 01 04 89 84 9d 90 01 04 8b 84 8d 90 01 04 03 84 9d 90 01 04 be 90 00 } //01 00 
		$a_02_1 = {99 f7 fe 8a 84 95 90 01 04 8b 55 08 8b 75 fc 30 04 32 ff 45 fc 8b 45 fc 3b 45 10 72 90 00 } //00 00 
		$a_00_2 = {78 } //a5 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Cryptinject_MTB_2{
	meta:
		description = "Trojan:Win32/Cryptinject!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {47 65 74 50 90 0a 10 00 c7 05 90 01 04 47 65 74 50 c7 05 90 01 04 72 6f 63 41 c7 05 90 01 04 64 64 72 65 90 02 20 68 90 1b 01 90 02 0a e8 90 00 } //01 00 
		$a_02_1 = {47 65 74 54 90 0a 10 00 c7 05 90 01 04 47 65 74 54 c7 05 90 01 04 69 63 6b 43 c7 05 90 01 04 6f 75 6e 74 90 02 20 68 90 1b 01 90 02 0a e8 90 00 } //01 00 
		$a_02_2 = {49 73 42 61 90 0a 10 00 c7 05 90 01 04 49 73 42 61 c7 05 90 01 04 64 52 65 61 c7 05 90 01 04 64 50 74 72 90 02 20 68 90 1b 01 90 02 0a e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}