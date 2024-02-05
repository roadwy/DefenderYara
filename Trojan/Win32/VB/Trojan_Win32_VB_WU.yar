
rule Trojan_Win32_VB_WU{
	meta:
		description = "Trojan:Win32/VB.WU,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 4d 69 63 72 6f 73 6f 66 74 20 56 69 73 75 61 6c 20 53 74 75 64 69 6f 5c 56 42 39 38 5c 56 42 36 2e 4f 4c 42 } //01 00 
		$a_00_1 = {50 00 6f 00 74 00 5f 00 44 00 72 00 6f 00 6e 00 65 00 20 00 42 00 79 00 20 00 50 00 6f 00 74 00 5f 00 4b 00 6e 00 69 00 67 00 68 00 74 00 } //01 00 
		$a_02_2 = {ff ff ff 02 00 00 00 89 95 90 01 01 ff ff ff c7 85 90 01 01 ff ff ff 08 40 00 00 90 00 } //01 00 
		$a_02_3 = {ff ff ff 8d 95 20 ff ff ff c7 85 90 01 01 ff ff ff 08 40 00 00 c7 85 90 01 01 ff ff ff 90 01 02 40 00 89 9d 20 ff ff ff ff d6 8d 95 90 01 01 ff ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}