
rule Trojan_Win32_Comrabot_A{
	meta:
		description = "Trojan:Win32/Comrabot.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 02 00 "
		
	strings :
		$a_02_0 = {8b 0f 8b 51 04 8b 4c 3a 90 01 01 8b 55 90 01 01 8b 01 8b 40 90 01 01 33 f6 56 52 8b 55 90 01 01 52 ff d0 90 00 } //01 00 
		$a_00_1 = {47 65 74 74 69 6e 67 20 74 61 73 6b 20 66 72 6f 6d 20 55 52 4c 3a } //01 00  Getting task from URL:
		$a_00_2 = {30 31 65 71 79 63 2e 63 6f 6d } //01 00  01eqyc.com
		$a_00_3 = {44 65 63 72 79 70 74 65 64 20 73 69 7a 65 3a 25 64 20 5b 25 73 5d } //01 00  Decrypted size:%d [%s]
		$a_00_4 = {43 6f 6d 72 61 64 65 20 56 45 52 } //00 00  Comrade VER
	condition:
		any of ($a_*)
 
}