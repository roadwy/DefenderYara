
rule Trojan_Win32_Orbus_A{
	meta:
		description = "Trojan:Win32/Orbus.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4c 00 6d 00 4e 00 77 00 62 00 41 00 3d 00 3d 00 } //1 LmNwbA==
		$a_01_1 = {57 00 46 00 41 00 74 00 4e 00 6a 00 51 00 3d 00 } //1 WFAtNjQ=
		$a_01_2 = {59 00 7a 00 70 00 63 00 52 00 47 00 56 00 7a 00 59 00 33 00 4a 00 70 00 64 00 47 00 6c 00 76 00 62 00 6c 00 78 00 4d 00 62 00 32 00 64 00 7a 00 } //1 YzpcRGVzY3JpdGlvblxMb2dz
		$a_01_3 = {5a 00 47 00 56 00 73 00 49 00 46 00 4e 00 55 00 55 00 6c 00 52 00 66 00 52 00 79 00 35 00 69 00 59 00 58 00 51 00 3d 00 } //1 ZGVsIFNUUlRfRy5iYXQ=
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}