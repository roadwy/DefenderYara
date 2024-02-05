
rule Trojan_Win32_ProxyChanger_D{
	meta:
		description = "Trojan:Win32/ProxyChanger.D,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 61 6e 69 72 6f 73 61 2e 63 6f 6d 2f 69 6e 63 6c 75 64 65 73 2f 61 72 65 6e 61 2d 69 6e 66 65 63 74 2f 63 6f 6e 74 61 5f 69 6e 66 65 63 74 73 2e 70 68 70 00 } //01 00 
		$a_03_1 = {32 30 30 2e 39 38 2e 31 34 39 2e 36 36 2f 90 02 40 2e 70 61 63 00 90 00 } //01 00 
		$a_01_2 = {50 4f 53 54 20 2f 69 6e 63 6c 75 64 65 73 2f 61 72 65 6e 61 2d 69 6e 66 65 63 74 2f 63 6f 6e 74 61 5f 69 6e 66 65 63 74 73 2e 70 68 70 20 48 54 54 50 2f 31 2e 30 } //00 00 
	condition:
		any of ($a_*)
 
}