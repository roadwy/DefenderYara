
rule Trojan_BAT_AsyncRAT_RDI_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.RDI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {66 62 63 38 63 36 30 66 2d 38 63 64 30 2d 34 62 30 34 2d 62 66 62 39 2d 62 36 64 65 65 31 32 61 37 34 64 39 } //1 fbc8c60f-8cd0-4b04-bfb9-b6dee12a74d9
		$a_01_1 = {57 69 6e 64 6f 77 73 41 70 70 31 } //1 WindowsApp1
		$a_01_2 = {6a 35 77 6b 79 4e 4a 6f 45 51 50 4c 61 38 52 73 70 77 } //1 j5wkyNJoEQPLa8Rspw
		$a_01_3 = {48 52 69 31 6f 53 4b 37 6b 31 4e 51 66 58 55 6d 77 42 } //1 HRi1oSK7k1NQfXUmwB
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}