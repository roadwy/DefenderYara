
rule Trojan_BAT_AgentTesla_AX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0a 02 16 28 ?? ?? ?? 0a 19 8d ?? ?? ?? 01 0a 06 16 7e ?? ?? ?? 04 a2 06 17 7e ?? ?? ?? 04 a2 06 18 20 ?? ?? ?? ?? 28 ?? ?? ?? 06 a2 06 73 ?? ?? ?? 06 26 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_BAT_AgentTesla_AX_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.AX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {20 86 05 00 00 95 80 1f 00 00 04 7e 28 00 00 04 1b 9a 1f 0b 8f 06 00 00 01 25 71 06 00 00 01 7e 28 00 00 04 18 9a 20 7e 07 00 00 95 61 81 06 00 00 01 7e 28 00 00 04 1b 9a 1f 0b 95 7e 28 00 00 04 18 9a 20 ec 02 00 00 95 40 9a 04 00 00 } //2
		$a_01_1 = {94 02 28 09 02 00 00 00 fa 25 33 00 16 00 00 01 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}
rule Trojan_BAT_AgentTesla_AX_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.AX!MTB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 76 00 34 00 2e 00 30 00 2e 00 33 00 30 00 33 00 31 00 39 00 5c 00 52 00 65 00 67 00 41 00 73 00 6d 00 2e 00 65 00 78 00 65 00 } //1 \Microsoft.NET\Framework\v4.0.30319\RegAsm.exe
		$a_01_1 = {2f 00 63 00 72 00 65 00 61 00 74 00 65 00 20 00 2f 00 73 00 63 00 20 00 4d 00 49 00 4e 00 55 00 54 00 45 00 20 00 2f 00 74 00 6e 00 } //1 /create /sc MINUTE /tn
		$a_01_2 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_3 = {2f 00 43 00 20 00 63 00 68 00 6f 00 69 00 63 00 65 00 20 00 2f 00 43 00 20 00 59 00 20 00 2f 00 4e 00 20 00 2f 00 44 00 20 00 59 00 20 00 2f 00 54 00 20 00 33 00 20 00 26 00 20 00 44 00 65 00 6c 00 } //1 /C choice /C Y /N /D Y /T 3 & Del
		$a_01_4 = {23 00 73 00 74 00 61 00 72 00 74 00 75 00 70 00 5f 00 6e 00 61 00 6d 00 65 00 23 00 } //1 #startup_name#
		$a_01_5 = {47 65 74 44 65 6c 65 67 61 74 65 46 6f 72 46 75 6e 63 74 69 6f 6e 50 6f 69 6e 74 65 72 } //1 GetDelegateForFunctionPointer
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}