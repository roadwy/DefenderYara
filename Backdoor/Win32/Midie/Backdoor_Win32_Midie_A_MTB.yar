
rule Backdoor_Win32_Midie_A_MTB{
	meta:
		description = "Backdoor:Win32/Midie.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b 1e 31 d3 89 1f 83 c6 04 83 c7 04 83 e9 01 89 c8 85 c1 75 eb } //10
		$a_00_1 = {47 65 74 46 69 72 6d 77 61 72 65 45 6e 76 69 72 6f 6e 6d 65 6e 74 56 61 72 69 61 62 6c 65 57 } //1 GetFirmwareEnvironmentVariableW
		$a_00_2 = {53 43 61 72 64 45 73 74 61 62 6c 69 73 68 43 6f 6e 74 65 78 74 } //1 SCardEstablishContext
		$a_00_3 = {50 5f b9 08 00 00 00 f3 a6 75 ef } //10
	condition:
		((#a_01_0  & 1)*10+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*10) >=21
 
}