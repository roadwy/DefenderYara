
rule Trojan_BAT_AgentTesla_ME_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 05 00 00 "
		
	strings :
		$a_03_0 = {06 07 03 07 91 02 7b 90 02 04 16 9a 6f 90 02 04 d2 02 7b 90 02 04 17 9a 6f 90 02 04 d2 61 d2 61 d2 9c 90 00 } //10
		$a_80_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //CreateInstance  2
		$a_80_2 = {41 63 74 69 76 61 74 6f 72 } //Activator  2
		$a_80_3 = {52 65 73 6f 75 72 63 65 4d 61 6e 61 67 65 72 } //ResourceManager  2
		$a_80_4 = {41 73 73 65 6d 62 6c 79 } //Assembly  2
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2+(#a_80_4  & 1)*2) >=18
 
}
rule Trojan_BAT_AgentTesla_ME_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.ME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 0d 00 00 "
		
	strings :
		$a_01_0 = {54 73 65 6d 61 63 68 50 6f 64 } //1 TsemachPod
		$a_01_1 = {44 65 62 75 67 } //1 Debug
		$a_01_2 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //1 MemoryStream
		$a_01_3 = {73 6e 61 70 73 68 6f 74 46 69 65 6c 64 } //1 snapshotField
		$a_01_4 = {67 65 74 5f 53 6e 61 70 73 68 6f 74 } //1 get_Snapshot
		$a_01_5 = {65 36 66 37 35 33 38 31 2d 38 64 33 38 2d 34 64 64 64 2d 38 65 30 33 2d 64 37 35 61 30 66 36 65 37 37 34 30 } //1 e6f75381-8d38-4ddd-8e03-d75a0f6e7740
		$a_01_6 = {50 61 73 73 77 6f 72 64 } //1 Password
		$a_01_7 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_8 = {67 65 74 5f 55 73 65 72 53 74 61 74 65 } //1 get_UserState
		$a_01_9 = {73 65 74 5f 50 61 73 73 77 6f 72 64 43 68 61 72 } //1 set_PasswordChar
		$a_01_10 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_11 = {52 75 6e 57 6f 72 6b 65 72 41 73 79 6e 63 } //1 RunWorkerAsync
		$a_01_12 = {47 65 74 42 79 74 65 73 } //1 GetBytes
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1) >=13
 
}
rule Trojan_BAT_AgentTesla_ME_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.ME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_03_0 = {0d 09 08 6f 67 00 00 0a 00 09 18 6f 68 00 00 0a 00 09 6f 69 00 00 0a 06 16 06 8e 69 6f 6a 00 00 0a 13 04 11 04 03 28 19 00 00 06 28 18 00 00 06 72 90 01 03 70 6f 6b 00 00 0a 80 0b 00 00 04 02 03 73 54 00 00 0a 13 05 2b 00 11 05 2a 90 00 } //1
		$a_01_1 = {65 63 38 34 32 36 62 65 2d 65 31 35 34 2d 34 66 30 65 2d 38 62 32 35 2d 62 63 66 32 63 38 64 62 30 32 62 34 } //1 ec8426be-e154-4f0e-8b25-bcf2c8db02b4
		$a_01_2 = {47 65 74 42 79 74 65 73 } //1 GetBytes
		$a_01_3 = {6b 65 79 69 73 64 6f 77 6e } //1 keyisdown
		$a_01_4 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_5 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
		$a_01_6 = {5a 65 72 6f 4f 72 4d 69 6e 75 73 } //1 ZeroOrMinus
		$a_01_7 = {53 61 66 65 48 61 6e 64 6c 65 } //1 SafeHandle
		$a_01_8 = {73 68 6c 6f 6d 69 32 5f 43 6c 69 63 6b } //1 shlomi2_Click
		$a_01_9 = {46 69 6e 61 6e 63 65 2e 46 72 61 6d 65 77 6f 72 6b 2e 54 79 70 65 73 2e 50 72 6f 70 65 72 74 69 65 73 } //1 Finance.Framework.Types.Properties
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=10
 
}