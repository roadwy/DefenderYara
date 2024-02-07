
rule Trojan_BAT_CoinMinerInj_MTB{
	meta:
		description = "Trojan:BAT/CoinMinerInj!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 00 72 00 6f 00 6f 00 74 00 5c 00 63 00 69 00 6d 00 76 00 32 00 } //01 00  \root\cimv2
		$a_01_1 = {53 00 65 00 6c 00 65 00 63 00 74 00 20 00 43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 4c 00 69 00 6e 00 65 00 20 00 66 00 72 00 6f 00 6d 00 20 00 57 00 69 00 6e 00 33 00 32 00 5f 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 20 00 77 00 68 00 65 00 72 00 65 00 20 00 4e 00 61 00 6d 00 65 00 3d 00 27 00 7b 00 30 00 7d 00 27 00 } //01 00  Select CommandLine from Win32_Process where Name='{0}'
		$a_01_2 = {43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 4c 00 69 00 6e 00 65 00 } //01 00  CommandLine
		$a_01_3 = {2d 00 2d 00 63 00 69 00 6e 00 69 00 74 00 2d 00 66 00 69 00 6e 00 64 00 2d 00 } //00 00  --cinit-find-
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_CoinMinerInj_MTB_2{
	meta:
		description = "Trojan:BAT/CoinMinerInj!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_01_0 = {3c 50 72 69 76 61 74 65 49 6d 70 6c 65 6d 65 6e 74 61 74 69 6f 6e 44 65 74 61 69 6c 73 3e 7b } //01 00  <PrivateImplementationDetails>{
		$a_01_1 = {73 65 74 5f 43 72 65 61 74 65 4e 6f 57 69 6e 64 6f 77 } //01 00  set_CreateNoWindow
		$a_01_2 = {24 24 6d 65 74 68 6f 64 30 78 36 } //01 00  $$method0x6
		$a_01_3 = {2f 00 63 00 20 00 73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 20 00 2f 00 63 00 72 00 65 00 61 00 74 00 65 00 20 00 2f 00 66 00 20 00 2f 00 73 00 63 00 20 00 6f 00 6e 00 6c 00 6f 00 67 00 6f 00 6e 00 20 00 2f 00 72 00 6c 00 20 00 68 00 69 00 67 00 68 00 65 00 73 00 74 00 20 00 2f 00 74 00 6e 00 20 00 22 00 } //01 00  /c schtasks /create /f /sc onlogon /rl highest /tn "
		$a_01_4 = {53 00 65 00 6c 00 65 00 63 00 74 00 20 00 43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 4c 00 69 00 6e 00 65 00 20 00 66 00 72 00 6f 00 6d 00 20 00 57 00 69 00 6e 00 33 00 32 00 5f 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 20 00 77 00 68 00 65 00 72 00 65 00 20 00 4e 00 61 00 6d 00 65 00 3d 00 27 00 7b 00 30 00 7d 00 27 00 } //01 00  Select CommandLine from Win32_Process where Name='{0}'
		$a_01_5 = {5c 00 72 00 6f 00 6f 00 74 00 5c 00 63 00 69 00 6d 00 76 00 32 00 } //01 00  \root\cimv2
		$a_01_6 = {43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 4c 00 69 00 6e 00 65 00 } //01 00  CommandLine
		$a_01_7 = {2d 00 2d 00 64 00 6f 00 6e 00 61 00 74 00 65 00 2d 00 6c 00 } //01 00  --donate-l
		$a_01_8 = {7b 00 25 00 52 00 41 00 4e 00 44 00 4f 00 4d 00 25 00 7d 00 } //01 00  {%RANDOM%}
		$a_01_9 = {7b 00 25 00 43 00 4f 00 4d 00 50 00 55 00 54 00 45 00 52 00 4e 00 41 00 4d 00 45 00 25 00 7d 00 } //00 00  {%COMPUTERNAME%}
	condition:
		any of ($a_*)
 
}