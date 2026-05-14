
rule Trojan_Win32_Lazy_LMS_MTB{
	meta:
		description = "Trojan:Win32/Lazy.LMS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 05 00 00 "
		
	strings :
		$a_01_0 = {c7 45 a0 00 01 00 00 89 45 9c 83 c4 0c 83 7e 14 07 8d 85 88 f5 ff ff 89 45 b8 c7 45 bc 00 04 00 00 76 } //20
		$a_81_1 = {64 6f 6e 67 66 61 6e 67 30 31 } //1 dongfang01
		$a_81_2 = {67 4d 69 63 72 6f 73 6f 66 74 20 55 70 64 61 74 65 20 43 6c 69 65 6e 74 } //2 gMicrosoft Update Client
		$a_81_3 = {5c 42 72 69 64 67 65 48 6f 73 74 2e 65 78 65 } //3 \BridgeHost.exe
		$a_81_4 = {55 73 65 72 2d 41 67 65 6e 74 3a 20 4d 6f 7a 69 6c 6c 61 2f 35 2e 30 20 28 57 69 6e 64 6f 77 73 20 4e 54 20 31 30 2e 30 3b 20 57 69 6e 36 34 3b 20 78 36 34 29 } //4 User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
	condition:
		((#a_01_0  & 1)*20+(#a_81_1  & 1)*1+(#a_81_2  & 1)*2+(#a_81_3  & 1)*3+(#a_81_4  & 1)*4) >=30
 
}