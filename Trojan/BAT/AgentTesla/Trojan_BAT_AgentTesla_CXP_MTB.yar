
rule Trojan_BAT_AgentTesla_CXP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CXP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_03_0 = {03 07 03 6f ?? ?? ?? 0a 5d 17 58 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 59 0c 90 09 0c 00 02 07 28 73 01 00 0a 28 74 01 00 0a } //1
		$a_01_1 = {47 65 74 54 79 70 65 } //1 GetType
		$a_01_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_3 = {46 72 6f 6d 42 61 73 65 36 34 } //1 FromBase64
		$a_01_4 = {54 6f 43 68 61 72 41 72 72 61 79 } //1 ToCharArray
		$a_01_5 = {00 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
rule Trojan_BAT_AgentTesla_CXP_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.CXP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 "
		
	strings :
		$a_01_0 = {07 11 04 07 11 04 91 08 11 04 91 61 d2 9c 11 04 17 58 13 04 11 04 08 8e 69 3f } //5
		$a_01_1 = {53 00 45 00 4c 00 45 00 43 00 54 00 20 00 2a 00 20 00 46 00 52 00 4f 00 4d 00 20 00 57 00 69 00 6e 00 33 00 32 00 5f 00 43 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 53 00 79 00 73 00 74 00 65 00 6d 00 } //1 SELECT * FROM Win32_ComputerSystem
		$a_01_2 = {53 00 65 00 6c 00 65 00 63 00 74 00 20 00 2a 00 20 00 66 00 72 00 6f 00 6d 00 20 00 57 00 69 00 6e 00 33 00 32 00 5f 00 4e 00 65 00 74 00 77 00 6f 00 72 00 6b 00 4c 00 6f 00 67 00 69 00 6e 00 50 00 72 00 6f 00 66 00 69 00 6c 00 65 00 20 00 77 00 68 00 65 00 72 00 65 00 20 00 4e 00 61 00 6d 00 65 00 20 00 4c 00 49 00 4b 00 45 00 20 00 27 00 25 00 } //1 Select * from Win32_NetworkLoginProfile where Name LIKE '%
		$a_01_3 = {73 00 65 00 6c 00 65 00 63 00 74 00 20 00 2a 00 20 00 66 00 72 00 6f 00 6d 00 20 00 57 00 69 00 6e 00 33 00 32 00 5f 00 55 00 73 00 65 00 72 00 41 00 63 00 63 00 6f 00 75 00 6e 00 74 00 } //1 select * from Win32_UserAccount
		$a_01_4 = {63 00 68 00 72 00 6f 00 6d 00 65 00 2e 00 65 00 78 00 65 00 } //1 chrome.exe
		$a_01_5 = {53 00 45 00 4c 00 45 00 43 00 54 00 20 00 41 00 64 00 64 00 72 00 65 00 73 00 73 00 57 00 69 00 64 00 74 00 68 00 20 00 46 00 52 00 4f 00 4d 00 20 00 57 00 69 00 6e 00 33 00 32 00 5f 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 6f 00 72 00 } //1 SELECT AddressWidth FROM Win32_Processor
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=10
 
}