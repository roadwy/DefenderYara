
rule Trojan_Win32_Qakbot_CO_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.CO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0c 00 00 "
		
	strings :
		$a_03_0 = {66 3b e4 74 ?? 8b 4d 14 83 d9 00 3a ed 74 ?? c3 89 45 10 89 4d 14 eb } //1
		$a_01_1 = {42 45 58 5f 47 65 74 49 6e 66 6f } //1 BEX_GetInfo
		$a_01_2 = {42 45 58 5f 49 6e 69 74 69 61 6c 69 7a 65 } //1 BEX_Initialize
		$a_01_3 = {42 45 58 5f 53 65 74 43 61 6c 6c 42 61 63 6b 73 } //1 BEX_SetCallBacks
		$a_01_4 = {42 45 58 5f 41 64 64 50 61 72 61 6d 65 74 65 72 } //1 BEX_AddParameter
		$a_01_5 = {42 45 58 5f 46 69 6e 61 6c 69 7a 65 } //1 BEX_Finalize
		$a_01_6 = {42 45 58 5f 45 78 65 63 75 74 65 52 65 61 64 } //1 BEX_ExecuteRead
		$a_01_7 = {42 45 58 5f 45 78 65 63 75 74 65 54 72 79 } //1 BEX_ExecuteTry
		$a_01_8 = {42 45 58 5f 45 78 65 63 75 74 65 57 72 69 74 65 } //1 BEX_ExecuteWrite
		$a_01_9 = {42 40 55 74 69 6c 73 32 40 49 6e 69 74 69 61 6c 69 7a 65 } //1 B@Utils2@Initialize
		$a_01_10 = {42 40 55 74 69 6c 73 32 40 46 69 6e 61 6c 69 7a 65 } //1 B@Utils2@Finalize
		$a_01_11 = {47 47 31 30 } //1 GG10
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1) >=12
 
}