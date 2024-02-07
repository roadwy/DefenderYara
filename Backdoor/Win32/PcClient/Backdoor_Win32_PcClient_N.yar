
rule Backdoor_Win32_PcClient_N{
	meta:
		description = "Backdoor:Win32/PcClient.N,SIGNATURE_TYPE_PEHSTR_EXT,34 00 33 00 0a 00 00 0a 00 "
		
	strings :
		$a_00_0 = {55 73 65 72 2d 41 67 65 6e 74 3a 20 4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 4d 53 49 45 20 37 2e 30 3b 20 57 69 6e 64 6f 77 73 20 4e 54 20 35 2e 32 3b 20 2e 4e 45 54 20 43 4c 52 20 31 2e 31 2e 34 33 32 32 3b 20 2e 4e 45 54 20 43 4c 52 20 32 2e 30 2e 35 30 37 32 37 3b 20 49 6e 66 6f 50 61 74 68 2e 31 29 } //0a 00  User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.2; .NET CLR 1.1.4322; .NET CLR 2.0.50727; InfoPath.1)
		$a_00_1 = {5c 73 76 63 68 6f 73 74 2e 65 78 65 20 2d 6b } //0a 00  \svchost.exe -k
		$a_00_2 = {53 65 72 76 69 63 65 44 6c 6c } //0a 00  ServiceDll
		$a_00_3 = {53 59 53 54 45 4d 5c 43 6f 6e 74 72 6f 6c 53 65 74 30 30 31 5c 53 65 72 76 69 63 65 73 5c 25 73 } //0a 00  SYSTEM\ControlSet001\Services\%s
		$a_01_4 = {50 33 c0 33 c0 33 c0 33 c0 33 c0 33 c0 } //01 00 
		$a_00_5 = {50 4f 53 54 20 68 74 74 70 3a 2f 2f 25 73 3a 25 64 2f 25 73 20 48 54 54 50 2f 31 2e 31 } //01 00  POST http://%s:%d/%s HTTP/1.1
		$a_00_6 = {47 6c 6f 62 61 6c 5c 25 73 2d 6b 65 79 2d 4d 65 74 75 78 } //01 00  Global\%s-key-Metux
		$a_00_7 = {6d 79 73 65 72 76 65 72 70 6f 72 74 } //01 00  myserverport
		$a_00_8 = {6d 79 73 65 72 76 65 72 61 64 64 72 } //01 00  myserveraddr
		$a_00_9 = {6d 79 74 68 72 65 61 64 69 64 } //00 00  mythreadid
	condition:
		any of ($a_*)
 
}