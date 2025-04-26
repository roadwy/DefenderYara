
rule Trojan_Win32_Tedy_SPDB_MTB{
	meta:
		description = "Trojan:Win32/Tedy.SPDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {41 45 46 63 57 75 74 76 71 56 7a 6a 6b 52 54 4c 50 6f 67 6f 62 77 43 59 68 79 } //1 AEFcWutvqVzjkRTLPogobwCYhy
		$a_01_1 = {41 42 79 73 75 51 50 76 78 76 74 50 57 78 53 64 6b 66 46 55 77 47 68 } //1 ABysuQPvxvtPWxSdkfFUwGh
		$a_01_2 = {41 41 78 46 64 4b 70 75 72 4f 51 47 44 73 4e 72 44 } //1 AAxFdKpurOQGDsNrD
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}