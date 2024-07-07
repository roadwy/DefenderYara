
rule Trojan_Win32_Agent_ADH{
	meta:
		description = "Trojan:Win32/Agent.ADH,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {42 41 53 45 53 52 56 2e 42 61 73 65 53 72 76 4e 6c 73 55 70 64 61 74 65 52 65 67 69 73 74 72 79 43 61 63 68 65 } //1 BASESRV.BaseSrvNlsUpdateRegistryCache
		$a_01_1 = {42 41 53 45 53 52 56 2e 42 61 73 65 53 65 74 50 72 6f 63 65 73 73 43 72 65 61 74 65 4e 6f 74 69 66 79 } //1 BASESRV.BaseSetProcessCreateNotify
		$a_01_2 = {42 41 53 45 53 52 56 2e 53 65 72 76 65 72 44 6c 6c 49 6e 69 74 69 61 6c 69 7a 61 74 69 6f 6e } //1 BASESRV.ServerDllInitialization
		$a_01_3 = {42 41 53 45 53 52 56 2e 42 61 73 65 53 72 76 4e 6c 73 4c 6f 67 6f 6e } //1 BASESRV.BaseSrvNlsLogon
		$a_01_4 = {42 41 53 45 53 52 56 2e 44 4c 4c } //1 BASESRV.DLL
		$a_02_5 = {50 6a 07 6a 2a 68 90 01 04 e8 02 35 00 00 53 8d 85 d4 fd ff ff 50 8d 45 eb 50 8d 45 f4 50 e8 47 33 00 00 6a 07 8d 45 eb 50 e8 83 30 00 00 8d 45 f4 50 50 53 53 be 90 01 04 56 e8 e7 fc ff ff ff d0 85 c0 0f 8c 3e 02 00 00 68 90 01 04 8d 45 e9 50 6a 09 6a 18 68 90 01 04 e8 af 34 00 00 53 8d 85 d4 fd ff ff 50 8d 45 e9 50 8d 45 f4 50 e8 f4 32 00 00 6a 09 8d 45 e9 50 e8 30 30 00 00 8d 45 f4 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_02_5  & 1)*1) >=6
 
}