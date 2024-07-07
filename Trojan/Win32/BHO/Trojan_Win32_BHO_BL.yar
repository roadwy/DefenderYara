
rule Trojan_Win32_BHO_BL{
	meta:
		description = "Trojan:Win32/BHO.BL,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6d 69 63 72 6f 73 6f 66 74 5f 6c 6f 63 6b } //1 microsoft_lock
		$a_01_1 = {73 79 73 6f 70 74 69 6f 6e 2e 69 6e 69 } //1 sysoption.ini
		$a_01_2 = {77 69 6e 69 6f 2e 73 79 73 } //1 winio.sys
		$a_01_3 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 28 00 52 00 29 00 20 00 52 00 65 00 64 00 20 00 49 00 53 00 41 00 4d 00 } //1 Microsoft (R) Red ISAM
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule Trojan_Win32_BHO_BL_2{
	meta:
		description = "Trojan:Win32/BHO.BL,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6d 69 63 72 6f 73 6f 66 74 5f 6c 6f 63 6b } //1 microsoft_lock
		$a_01_1 = {77 69 6e 69 6f 2e 73 79 73 } //1 winio.sys
		$a_01_2 = {49 00 6e 00 74 00 65 00 72 00 6e 00 65 00 74 00 20 00 45 00 78 00 74 00 65 00 6e 00 73 00 69 00 6f 00 6e 00 73 00 20 00 66 00 6f 00 72 00 20 00 57 00 69 00 6e 00 33 00 32 00 } //1 Internet Extensions for Win32
		$a_01_3 = {39 37 34 42 42 44 45 36 2d 39 32 35 41 2d 34 37 30 32 2d 41 31 33 33 2d 43 41 46 45 35 43 33 46 35 37 38 34 } //1 974BBDE6-925A-4702-A133-CAFE5C3F5784
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}