
rule Trojan_Win32_SKNet{
	meta:
		description = "Trojan:Win32/SKNet,SIGNATURE_TYPE_PEHSTR,2d 00 2d 00 06 00 00 0a 00 "
		
	strings :
		$a_01_0 = {64 69 63 00 70 61 73 73 77 64 00 00 75 6e 61 6d 65 00 } //0a 00 
		$a_01_1 = {69 65 38 32 73 2a 2a 31 00 00 00 00 6d 73 31 24 40 33 33 77 00 00 00 00 50 61 72 61 6d 65 74 65 72 73 } //0a 00 
		$a_01_2 = {53 51 4c 20 d7 a2 c8 eb ba f3 cc a8 b2 e5 bc fe 00 } //0a 00 
		$a_01_3 = {42 61 6e 67 77 6f 00 } //05 00 
		$a_01_4 = {53 4b 4e 65 74 53 72 76 5f 44 4c 4c 2e } //05 00  SKNetSrv_DLL.
		$a_01_5 = {5b 21 5d 44 65 76 69 63 65 49 6f 43 6f 6e 74 72 6f 6c 20 66 61 69 6c 65 64 2e 20 6d 61 79 62 65 20 68 61 73 20 62 65 65 6e 20 69 6e 6a 65 63 74 65 64 21 } //00 00  [!]DeviceIoControl failed. maybe has been injected!
	condition:
		any of ($a_*)
 
}