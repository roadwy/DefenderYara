
rule Trojan_Win32_Tulong_XA_MTB{
	meta:
		description = "Trojan:Win32/Tulong.XA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {31 32 31 2e 31 32 34 2e 31 32 34 2e 32 31 30 } //01 00  121.124.124.210
		$a_01_1 = {5c 4d 79 52 61 74 53 65 72 76 65 72 5c 52 65 6c 65 61 73 65 5c 4d 79 52 61 74 53 65 72 76 65 72 2e 70 64 62 } //01 00  \MyRatServer\Release\MyRatServer.pdb
		$a_01_2 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //01 00  IsDebuggerPresent
		$a_01_3 = {47 65 74 54 69 63 6b 43 6f 75 6e 74 36 34 } //01 00  GetTickCount64
		$a_80_4 = {40 44 4f 57 4e 46 49 4c 45 } //@DOWNFILE  01 00 
		$a_80_5 = {4f 6e 6c 69 6e 65 3a 25 73 3a 25 73 3a 25 73 3a 25 73 } //Online:%s:%s:%s:%s  01 00 
		$a_80_6 = {40 55 50 46 49 4c 45 } //@UPFILE  00 00 
	condition:
		any of ($a_*)
 
}