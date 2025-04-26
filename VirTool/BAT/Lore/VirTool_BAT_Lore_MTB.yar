
rule VirTool_BAT_Lore_MTB{
	meta:
		description = "VirTool:BAT/Lore!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 6e 61 6b 65 4c 69 62 2e 64 6c 6c } //1 SnakeLib.dll
		$a_01_1 = {53 6e 61 6b 65 2e 53 49 47 44 55 2e 72 65 73 6f 75 72 63 65 73 } //1 Snake.SIGDU.resources
		$a_01_2 = {41 70 70 44 6f 6d 61 69 6e } //1 AppDomain
		$a_01_3 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //1 get_CurrentDomain
		$a_01_4 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule VirTool_BAT_Lore_MTB_2{
	meta:
		description = "VirTool:BAT/Lore!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {61 73 64 61 64 61 64 } //1 asdadad
		$a_81_1 = {57 72 69 74 65 } //1 Write
		$a_81_2 = {52 65 61 64 42 79 74 65 } //1 ReadByte
		$a_81_3 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
		$a_81_4 = {42 6c 6f 63 6b 43 6f 70 79 } //1 BlockCopy
		$a_81_5 = {24 63 34 30 39 39 65 34 63 2d 35 39 62 65 2d 34 38 35 64 2d 62 30 62 66 2d 33 34 64 65 61 32 61 64 36 62 34 62 } //1 $c4099e4c-59be-485d-b0bf-34dea2ad6b4b
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}
rule VirTool_BAT_Lore_MTB_3{
	meta:
		description = "VirTool:BAT/Lore!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {67 65 74 5f 42 } //1 get_B
		$a_01_1 = {67 65 74 5f 47 } //1 get_G
		$a_01_2 = {67 65 74 5f 52 } //1 get_R
		$a_01_3 = {43 00 6f 00 72 00 65 00 44 00 42 00 } //1 CoreDB
		$a_01_4 = {52 61 7a 65 72 53 79 6e 61 70 73 65 2e 64 6c 6c } //1 RazerSynapse.dll
		$a_01_5 = {74 00 65 00 6d 00 70 00 75 00 72 00 69 00 2e 00 6f 00 72 00 67 00 2f 00 43 00 6f 00 72 00 65 00 44 00 42 00 2e 00 78 00 73 00 64 00 } //1 tempuri.org/CoreDB.xsd
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
rule VirTool_BAT_Lore_MTB_4{
	meta:
		description = "VirTool:BAT/Lore!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {4d 41 52 43 55 53 2e 64 6c 6c } //1 MARCUS.dll
		$a_01_1 = {3c 4d 6f 64 75 6c 65 3e } //1 <Module>
		$a_01_2 = {53 79 73 74 65 6d 2e 49 4f 2e 43 6f 6d 70 72 65 73 73 69 6f 6e } //1 System.IO.Compression
		$a_01_3 = {42 69 74 6d 61 70 } //1 Bitmap
		$a_01_4 = {72 65 73 6f 75 72 63 65 5f 6e 61 6d 65 } //1 resource_name
		$a_01_5 = {70 72 6f 6a 65 63 74 5f 6e 61 6d 65 } //1 project_name
		$a_01_6 = {41 70 70 44 6f 6d 61 69 6e } //1 AppDomain
		$a_01_7 = {53 79 73 74 65 6d 2e 53 65 63 75 72 69 74 79 2e 50 6f 6c 69 63 79 } //1 System.Security.Policy
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}
rule VirTool_BAT_Lore_MTB_5{
	meta:
		description = "VirTool:BAT/Lore!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {55 6e 68 6f 6f 6b 2e 64 6c 6c } //1 Unhook.dll
		$a_01_1 = {53 6d 61 72 74 41 73 73 65 6d 62 6c 79 2e 48 6f 75 73 65 4f 66 43 61 72 64 73 } //1 SmartAssembly.HouseOfCards
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_3 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //1 GetExecutingAssembly
		$a_01_4 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 VirtualAlloc
		$a_01_5 = {51 41 46 41 53 54 } //1 QAFAST
		$a_01_6 = {55 6e 68 6f 6f 6b 2e 67 2e 72 65 73 6f 75 72 63 65 73 } //1 Unhook.g.resources
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}
rule VirTool_BAT_Lore_MTB_6{
	meta:
		description = "VirTool:BAT/Lore!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //1 DebuggerBrowsableState
		$a_01_1 = {73 65 74 5f 4b 65 79 53 69 7a 65 } //1 set_KeySize
		$a_01_2 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
		$a_01_3 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
		$a_01_4 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_5 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
		$a_01_6 = {5a 00 49 00 6d 00 42 00 4f 00 5a 00 58 00 2e 00 64 00 6c 00 6c 00 } //1 ZImBOZX.dll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}
rule VirTool_BAT_Lore_MTB_7{
	meta:
		description = "VirTool:BAT/Lore!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 0f 00 00 "
		
	strings :
		$a_01_0 = {76 61 72 31 } //1 var1
		$a_01_1 = {76 61 72 32 } //1 var2
		$a_01_2 = {76 61 72 33 } //1 var3
		$a_01_3 = {75 67 7a 31 } //1 ugz1
		$a_01_4 = {75 67 7a 33 } //1 ugz3
		$a_01_5 = {70 72 6f 6a 6e 61 6d 65 } //1 projname
		$a_01_6 = {47 75 72 75 } //1 Guru
		$a_01_7 = {67 65 74 5f 58 } //1 get_X
		$a_01_8 = {67 65 74 5f 59 } //1 get_Y
		$a_01_9 = {67 65 74 5f 52 } //1 get_R
		$a_01_10 = {67 65 74 5f 42 } //1 get_B
		$a_01_11 = {67 65 74 5f 47 } //1 get_G
		$a_01_12 = {4e 65 77 4c 61 74 65 42 69 6e 64 69 6e 67 } //1 NewLateBinding
		$a_01_13 = {4c 61 74 65 43 61 6c 6c } //1 LateCall
		$a_01_14 = {53 79 73 74 65 6d 2e 54 68 72 65 61 64 69 6e 67 } //1 System.Threading
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1) >=15
 
}
rule VirTool_BAT_Lore_MTB_8{
	meta:
		description = "VirTool:BAT/Lore!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {58 55 4b 65 6c 72 6f 75 70 68 67 50 78 69 62 46 4b 43 76 76 6e 66 77 53 65 52 56 6d 2e 64 6c 6c } //1 XUKelrouphgPxibFKCvvnfwSeRVm.dll
		$a_01_1 = {3c 4d 6f 64 75 6c 65 3e } //1 <Module>
		$a_01_2 = {58 55 4b 65 6c 72 6f 75 70 68 67 50 78 69 62 46 4b 43 76 76 6e 66 77 53 65 52 56 6d } //1 XUKelrouphgPxibFKCvvnfwSeRVm
		$a_01_3 = {44 65 73 65 72 69 61 6c 69 7a 65 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 Deserialize.Resources.resources
		$a_01_4 = {44 65 73 65 72 69 61 6c 69 7a 65 2e 52 75 6e 50 65 34 2e 64 65 63 } //1 Deserialize.RunPe4.dec
		$a_01_5 = {44 65 73 65 72 69 61 6c 69 7a 65 2e 56 4d 44 65 74 65 63 74 6f 72 2e 64 65 63 } //1 Deserialize.VMDetector.dec
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
rule VirTool_BAT_Lore_MTB_9{
	meta:
		description = "VirTool:BAT/Lore!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 0e 00 00 "
		
	strings :
		$a_01_0 = {4d 41 52 43 55 53 2e 64 6c 6c } //1 MARCUS.dll
		$a_01_1 = {3c 4d 6f 64 75 6c 65 3e } //1 <Module>
		$a_01_2 = {4a 61 72 69 63 6f } //1 Jarico
		$a_01_3 = {53 79 73 74 65 6d 2e 49 4f 2e 43 6f 6d 70 72 65 73 73 69 6f 6e } //1 System.IO.Compression
		$a_01_4 = {72 65 73 5f 6e 61 6d 65 } //1 res_name
		$a_01_5 = {70 72 6f 6a 5f 6e 61 6d 65 } //1 proj_name
		$a_01_6 = {42 75 74 61 } //1 Buta
		$a_01_7 = {72 65 73 6f 75 72 63 65 5f 6e 61 6d 65 } //1 resource_name
		$a_01_8 = {70 72 6f 6a 65 63 74 5f 6e 61 6d 65 } //1 project_name
		$a_01_9 = {67 65 74 5f 52 } //1 get_R
		$a_01_10 = {67 65 74 5f 47 } //1 get_G
		$a_01_11 = {67 65 74 5f 42 } //1 get_B
		$a_01_12 = {67 65 74 5f 57 69 64 74 68 } //1 get_Width
		$a_01_13 = {67 65 74 5f 48 65 69 67 68 74 } //1 get_Height
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1) >=14
 
}
rule VirTool_BAT_Lore_MTB_10{
	meta:
		description = "VirTool:BAT/Lore!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0c 00 00 "
		
	strings :
		$a_01_0 = {44 33 4c 4c 43 4f 44 45 } //1 D3LLCODE
		$a_01_1 = {45 78 65 63 73 54 41 52 54 75 50 } //1 ExecsTARTuP
		$a_01_2 = {55 44 65 63 72 79 70 74 55 } //1 UDecryptU
		$a_01_3 = {67 65 74 5f 49 56 } //1 get_IV
		$a_01_4 = {73 65 74 5f 49 56 } //1 set_IV
		$a_01_5 = {67 65 74 5f 54 65 73 6c 61 } //1 get_Tesla
		$a_01_6 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //1 DownloadFile
		$a_01_7 = {55 70 64 61 74 65 49 6e 69 46 69 6c 65 } //1 UpdateIniFile
		$a_01_8 = {73 65 74 5f 55 73 65 53 68 65 6c 6c 45 78 65 63 75 74 65 } //1 set_UseShellExecute
		$a_01_9 = {73 65 74 5f 43 72 65 61 74 65 4e 6f 57 69 6e 64 6f 77 } //1 set_CreateNoWindow
		$a_01_10 = {41 00 70 00 24 00 70 00 24 00 65 00 78 00 } //1 Ap$p$ex
		$a_01_11 = {49 00 6e 00 24 00 4a 00 24 00 63 00 74 00 30 00 72 00 } //1 In$J$ct0r
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1) >=12
 
}
rule VirTool_BAT_Lore_MTB_11{
	meta:
		description = "VirTool:BAT/Lore!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 12 00 00 "
		
	strings :
		$a_01_0 = {76 61 72 31 } //1 var1
		$a_01_1 = {76 61 72 32 } //1 var2
		$a_01_2 = {76 61 72 33 } //1 var3
		$a_01_3 = {75 67 7a 31 } //1 ugz1
		$a_01_4 = {75 67 7a 33 } //1 ugz3
		$a_01_5 = {70 72 6f 6a 6e 61 6d 65 } //1 projname
		$a_01_6 = {67 65 74 5f 4a 6f 6e 61 73 } //1 get_Jonas
		$a_01_7 = {73 65 74 5f 4a 6f 6e 61 73 } //1 set_Jonas
		$a_01_8 = {58 65 48 00 68 65 78 } //1
		$a_01_9 = {43 61 6c 6c 42 79 4e 61 6d 65 } //1 CallByName
		$a_01_10 = {67 65 74 5f 58 } //1 get_X
		$a_01_11 = {67 65 74 5f 59 } //1 get_Y
		$a_01_12 = {73 65 74 5f 58 } //1 set_X
		$a_01_13 = {73 65 74 5f 59 } //1 set_Y
		$a_01_14 = {41 70 70 44 6f 6d 61 69 6e } //1 AppDomain
		$a_01_15 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //1 get_CurrentDomain
		$a_01_16 = {53 79 73 74 65 6d 2e 54 68 72 65 61 64 69 6e 67 } //1 System.Threading
		$a_01_17 = {49 00 6e 00 76 00 6f 00 6b 00 65 00 } //1 Invoke
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1+(#a_01_17  & 1)*1) >=18
 
}
rule VirTool_BAT_Lore_MTB_12{
	meta:
		description = "VirTool:BAT/Lore!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 0d 00 00 "
		
	strings :
		$a_01_0 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_1 = {49 6e 76 65 72 73 65 51 } //1 InverseQ
		$a_01_2 = {43 72 79 70 74 6f 53 74 72 65 61 6d } //1 CryptoStream
		$a_01_3 = {41 70 70 44 6f 6d 61 69 6e } //1 AppDomain
		$a_01_4 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //1 get_CurrentDomain
		$a_01_5 = {42 69 74 6d 61 70 } //1 Bitmap
		$a_01_6 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
		$a_01_7 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_8 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
		$a_01_9 = {73 65 74 5f 4b 65 79 } //1 set_Key
		$a_01_10 = {64 65 61 64 20 63 6f 64 65 54 } //1 dead codeT
		$a_01_11 = {53 74 72 69 70 41 66 74 65 72 4f 62 66 75 73 63 61 74 69 6f 6e } //1 StripAfterObfuscation
		$a_01_12 = {50 68 6f 74 6f 44 69 72 65 63 74 6f 72 5f 32 2e 64 6c 6c } //1 PhotoDirector_2.dll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1) >=13
 
}
rule VirTool_BAT_Lore_MTB_13{
	meta:
		description = "VirTool:BAT/Lore!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 10 00 00 "
		
	strings :
		$a_01_0 = {76 61 72 31 } //1 var1
		$a_01_1 = {76 61 72 32 } //1 var2
		$a_01_2 = {76 61 72 33 } //1 var3
		$a_01_3 = {3c 4d 6f 64 75 6c 65 3e } //1 <Module>
		$a_01_4 = {67 65 74 5f 46 69 6c 65 4e 61 6d 65 } //1 get_FileName
		$a_01_5 = {70 72 6f 6a 6e 61 6d 65 } //1 projname
		$a_01_6 = {53 79 73 74 65 6d 2e 54 68 72 65 61 64 69 6e 67 } //1 System.Threading
		$a_01_7 = {53 79 73 74 65 6d 2e 44 72 61 77 69 6e 67 } //1 System.Drawing
		$a_01_8 = {67 65 74 5f 57 69 64 74 68 } //1 get_Width
		$a_01_9 = {67 65 74 5f 4c 65 6e 67 74 68 } //1 get_Length
		$a_01_10 = {47 65 74 50 69 78 65 6c } //1 GetPixel
		$a_01_11 = {43 6f 6d 70 6f 6e 65 6e 74 52 65 73 6f 75 72 63 65 4d 61 6e 61 67 65 72 } //1 ComponentResourceManager
		$a_01_12 = {67 65 74 5f 4a 6f 6e 61 73 } //1 get_Jonas
		$a_01_13 = {73 65 74 5f 4a 6f 6e 61 73 } //1 set_Jonas
		$a_01_14 = {4c 00 6f 00 61 00 64 00 } //1 Load
		$a_01_15 = {2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 .Resources
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1) >=16
 
}
rule VirTool_BAT_Lore_MTB_14{
	meta:
		description = "VirTool:BAT/Lore!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 0e 00 00 "
		
	strings :
		$a_01_0 = {3c 4d 6f 64 75 6c 65 3e } //1 <Module>
		$a_01_1 = {67 65 74 5f 52 } //1 get_R
		$a_01_2 = {67 65 74 5f 47 } //1 get_G
		$a_01_3 = {67 65 74 5f 42 } //1 get_B
		$a_01_4 = {72 65 73 6f 75 72 63 65 5f 6e 61 6d 65 } //1 resource_name
		$a_01_5 = {70 72 6f 6a 65 63 74 5f 6e 61 6d 65 } //1 project_name
		$a_01_6 = {53 79 73 74 65 6d 2e 54 68 72 65 61 64 69 6e 67 } //1 System.Threading
		$a_01_7 = {53 79 73 74 65 6d 2e 44 72 61 77 69 6e 67 } //1 System.Drawing
		$a_01_8 = {67 65 74 5f 57 69 64 74 68 } //1 get_Width
		$a_01_9 = {67 65 74 5f 4c 65 6e 67 74 68 } //1 get_Length
		$a_01_10 = {67 65 74 5f 48 65 69 67 68 74 } //1 get_Height
		$a_01_11 = {2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 .Properties.Resources
		$a_01_12 = {45 00 6e 00 74 00 72 00 79 00 50 00 6f 00 69 00 6e 00 74 00 } //1 EntryPoint
		$a_01_13 = {49 00 6e 00 76 00 6f 00 6b 00 65 00 } //1 Invoke
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1) >=14
 
}
rule VirTool_BAT_Lore_MTB_15{
	meta:
		description = "VirTool:BAT/Lore!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 0d 00 00 "
		
	strings :
		$a_01_0 = {3c 4d 6f 64 75 6c 65 3e } //1 <Module>
		$a_01_1 = {53 79 73 74 65 6d 2e 49 4f } //1 System.IO
		$a_01_2 = {67 65 74 5f 49 73 50 75 62 6c 69 63 } //1 get_IsPublic
		$a_01_3 = {53 79 73 74 65 6d 2e 43 6f 6c 6c 65 63 74 69 6f 6e 73 2e 47 65 6e 65 72 69 63 } //1 System.Collections.Generic
		$a_01_4 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_5 = {43 6f 6d 70 72 65 73 73 69 6f 6e 4d 6f 64 65 } //1 CompressionMode
		$a_01_6 = {67 65 74 5f 44 65 63 6c 61 72 69 6e 67 54 79 70 65 } //1 get_DeclaringType
		$a_01_7 = {47 5a 69 70 53 74 72 65 61 6d } //1 GZipStream
		$a_01_8 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //1 get_CurrentDomain
		$a_01_9 = {53 79 73 74 65 6d 2e 49 4f 2e 43 6f 6d 70 72 65 73 73 69 6f 6e } //1 System.IO.Compression
		$a_01_10 = {53 79 73 74 65 6d 2e 52 65 66 6c 65 63 74 69 6f 6e } //1 System.Reflection
		$a_01_11 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
		$a_01_12 = {4c 00 6f 00 21 00 61 00 64 00 } //1 Lo!ad
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1) >=13
 
}
rule VirTool_BAT_Lore_MTB_16{
	meta:
		description = "VirTool:BAT/Lore!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 12 00 00 "
		
	strings :
		$a_01_0 = {3c 4d 6f 64 75 6c 65 3e } //1 <Module>
		$a_01_1 = {3c 50 72 69 76 61 74 65 49 6d 70 6c 65 6d 65 6e 74 61 74 69 6f 6e 44 65 74 61 69 6c 73 3e } //1 <PrivateImplementationDetails>
		$a_01_2 = {67 65 74 5f 52 } //1 get_R
		$a_01_3 = {67 65 74 5f 47 } //1 get_G
		$a_01_4 = {67 65 74 5f 42 } //1 get_B
		$a_01_5 = {70 72 6f 6a 5f 6e 61 6d 65 } //1 proj_name
		$a_01_6 = {72 65 73 5f 6e 61 6d 65 } //1 res_name
		$a_01_7 = {53 79 73 74 65 6d 2e 54 68 72 65 61 64 69 6e 67 } //1 System.Threading
		$a_01_8 = {53 79 73 74 65 6d 2e 44 72 61 77 69 6e 67 } //1 System.Drawing
		$a_01_9 = {67 65 74 5f 53 69 7a 65 } //1 get_Size
		$a_01_10 = {67 65 74 5f 57 69 64 74 68 } //1 get_Width
		$a_01_11 = {67 65 74 5f 4c 65 6e 67 74 68 } //1 get_Length
		$a_01_12 = {67 65 74 5f 48 65 69 67 68 74 } //1 get_Height
		$a_01_13 = {47 65 74 50 69 78 65 6c } //1 GetPixel
		$a_01_14 = {42 69 74 6d 61 70 } //1 Bitmap
		$a_01_15 = {41 70 68 72 6f 64 69 74 65 } //1 Aphrodite
		$a_01_16 = {41 6d 70 68 69 74 72 69 74 65 } //1 Amphitrite
		$a_01_17 = {41 6e 74 68 65 69 61 } //1 Antheia
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1+(#a_01_17  & 1)*1) >=18
 
}
rule VirTool_BAT_Lore_MTB_17{
	meta:
		description = "VirTool:BAT/Lore!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 12 00 00 "
		
	strings :
		$a_01_0 = {43 6f 72 65 4c 6f 61 64 } //1 CoreLoad
		$a_01_1 = {67 65 74 5f 43 6f 72 65 50 72 6f 70 65 72 74 79 } //1 get_CoreProperty
		$a_01_2 = {73 65 74 5f 43 6f 72 65 50 72 6f 70 65 72 74 79 } //1 set_CoreProperty
		$a_01_3 = {43 6f 72 65 4c 6f 61 64 65 72 } //1 CoreLoader
		$a_01_4 = {41 70 70 44 6f 6d 61 69 6e } //1 AppDomain
		$a_01_5 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //1 get_CurrentDomain
		$a_01_6 = {67 65 74 5f 45 6e 74 72 79 50 6f 69 6e 74 } //1 get_EntryPoint
		$a_01_7 = {4d 65 74 68 6f 64 42 61 73 65 } //1 MethodBase
		$a_01_8 = {49 6e 76 6f 6b 65 } //1 Invoke
		$a_01_9 = {67 65 74 5f 53 69 7a 65 } //1 get_Size
		$a_01_10 = {67 65 74 5f 57 69 64 74 68 } //1 get_Width
		$a_01_11 = {47 65 74 50 69 78 65 6c } //1 GetPixel
		$a_01_12 = {54 6f 41 72 67 62 } //1 ToArgb
		$a_01_13 = {42 69 74 43 6f 6e 76 65 72 74 65 72 } //1 BitConverter
		$a_01_14 = {47 65 74 42 79 74 65 73 } //1 GetBytes
		$a_01_15 = {42 75 66 66 65 72 } //1 Buffer
		$a_01_16 = {42 6c 6f 63 6b 43 6f 70 79 } //1 BlockCopy
		$a_01_17 = {43 6f 72 65 50 72 6f 70 65 72 74 79 } //1 CoreProperty
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1+(#a_01_17  & 1)*1) >=18
 
}
rule VirTool_BAT_Lore_MTB_18{
	meta:
		description = "VirTool:BAT/Lore!MTB,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 11 00 00 "
		
	strings :
		$a_01_0 = {76 61 72 31 } //1 var1
		$a_01_1 = {76 61 72 32 } //1 var2
		$a_01_2 = {76 61 72 33 } //1 var3
		$a_01_3 = {3c 4d 6f 64 75 6c 65 3e } //1 <Module>
		$a_01_4 = {53 79 73 74 65 6d 2e 54 68 72 65 61 64 69 6e 67 } //1 System.Threading
		$a_01_5 = {53 79 73 74 65 6d 2e 44 72 61 77 69 6e 67 } //1 System.Drawing
		$a_01_6 = {67 65 74 5f 57 69 64 74 68 } //1 get_Width
		$a_01_7 = {67 65 74 5f 4c 65 6e 67 74 68 } //1 get_Length
		$a_01_8 = {47 65 74 50 69 78 65 6c } //1 GetPixel
		$a_01_9 = {67 65 74 5f 52 65 73 6f 75 72 63 65 4d 61 6e 61 67 65 72 } //1 get_ResourceManager
		$a_01_10 = {42 69 74 43 6f 6e 76 65 72 74 65 72 } //1 BitConverter
		$a_01_11 = {41 63 74 69 76 61 74 6f 72 } //1 Activator
		$a_01_12 = {67 65 74 5f 57 72 61 70 70 65 64 4f 62 6a 65 63 74 } //1 get_WrappedObject
		$a_01_13 = {73 65 74 5f 57 72 61 70 70 65 64 4f 62 6a 65 63 74 } //1 set_WrappedObject
		$a_01_14 = {47 65 74 45 6e 74 72 79 41 73 73 65 6d 62 6c 79 } //1 GetEntryAssembly
		$a_01_15 = {4c 00 6f 00 61 00 64 00 } //1 Load
		$a_01_16 = {2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 .Resources
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1) >=17
 
}
rule VirTool_BAT_Lore_MTB_19{
	meta:
		description = "VirTool:BAT/Lore!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_01_0 = {5c 00 6e 00 6f 00 74 00 65 00 70 00 61 00 64 00 2e 00 65 00 78 00 65 00 } //1 \notepad.exe
		$a_01_1 = {5c 00 52 00 65 00 67 00 41 00 73 00 6d 00 2e 00 65 00 78 00 65 00 } //1 \RegAsm.exe
		$a_01_2 = {5c 00 76 00 62 00 63 00 2e 00 65 00 78 00 65 00 } //1 \vbc.exe
		$a_01_3 = {5c 00 63 00 76 00 74 00 72 00 65 00 73 00 2e 00 65 00 78 00 65 00 } //1 \cvtres.exe
		$a_01_4 = {5c 00 49 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 55 00 74 00 69 00 6c 00 2e 00 65 00 78 00 65 00 } //1 \InstallUtil.exe
		$a_01_5 = {5c 00 41 00 70 00 70 00 4c 00 61 00 75 00 6e 00 63 00 68 00 2e 00 65 00 78 00 65 00 } //1 \AppLaunch.exe
		$a_01_6 = {5c 00 73 00 76 00 63 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 } //1 \svchost.exe
		$a_01_7 = {54 41 53 4b 4b 49 4c 6b 69 6c 6c 6c } //1 TASKKILkilll
		$a_01_8 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //1 DebuggerHiddenAttribute
		$a_01_9 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerBrowsableAttribute
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=10
 
}
rule VirTool_BAT_Lore_MTB_20{
	meta:
		description = "VirTool:BAT/Lore!MTB,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 11 00 00 "
		
	strings :
		$a_01_0 = {3c 50 72 69 76 61 74 65 49 6d 70 6c 65 6d 65 6e 74 61 74 69 6f 6e 44 65 74 61 69 6c 73 3e 7b } //1 <PrivateImplementationDetails>{
		$a_01_1 = {67 65 74 5f 56 61 6c 75 65 } //1 get_Value
		$a_01_2 = {73 65 74 5f 56 61 6c 75 65 } //1 set_Value
		$a_01_3 = {76 61 72 31 } //1 var1
		$a_01_4 = {76 61 72 32 } //1 var2
		$a_01_5 = {76 61 72 33 } //1 var3
		$a_01_6 = {67 65 74 5f 57 69 64 74 68 } //1 get_Width
		$a_01_7 = {67 65 74 5f 53 69 7a 65 } //1 get_Size
		$a_01_8 = {47 65 74 50 69 78 65 6c } //1 GetPixel
		$a_01_9 = {70 72 6f 6a 65 63 74 6e 61 6d 65 } //1 projectname
		$a_01_10 = {73 65 74 5f 53 65 72 76 65 72 50 61 67 65 54 69 6d 65 4c 69 6d 69 74 } //1 set_ServerPageTimeLimit
		$a_01_11 = {67 65 74 5f 57 72 61 70 70 65 64 4f 62 6a 65 63 74 } //1 get_WrappedObject
		$a_01_12 = {73 65 74 5f 57 72 61 70 70 65 64 4f 62 6a 65 63 74 } //1 set_WrappedObject
		$a_01_13 = {53 79 73 74 65 6d 2e 54 68 72 65 61 64 69 6e 67 } //1 System.Threading
		$a_01_14 = {43 72 65 61 74 65 44 65 6c 65 67 61 74 65 } //1 CreateDelegate
		$a_81_15 = {49 6e 76 6f 6b 65 } //1 Invoke
		$a_81_16 = {2e 52 65 73 6f 75 72 63 65 73 } //1 .Resources
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_81_15  & 1)*1+(#a_81_16  & 1)*1) >=17
 
}
rule VirTool_BAT_Lore_MTB_21{
	meta:
		description = "VirTool:BAT/Lore!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 14 00 00 "
		
	strings :
		$a_01_0 = {76 61 72 31 } //1 var1
		$a_01_1 = {76 61 72 32 } //1 var2
		$a_01_2 = {76 61 72 33 } //1 var3
		$a_01_3 = {70 72 6f 6a 6e 61 6d 65 } //1 projname
		$a_01_4 = {53 79 73 74 65 6d 2e 44 72 61 77 69 6e 67 } //1 System.Drawing
		$a_01_5 = {53 79 73 74 65 6d 2e 54 68 72 65 61 64 69 6e 67 } //1 System.Threading
		$a_01_6 = {67 65 74 5f 4c 65 6e 67 74 68 } //1 get_Length
		$a_01_7 = {67 65 74 5f 53 69 7a 65 } //1 get_Size
		$a_01_8 = {67 65 74 5f 57 69 64 74 68 } //1 get_Width
		$a_01_9 = {67 65 74 5f 48 65 69 67 68 74 } //1 get_Height
		$a_01_10 = {67 65 74 5f 57 72 61 70 70 65 64 4f 62 6a 65 63 74 } //1 get_WrappedObject
		$a_01_11 = {73 65 74 5f 57 72 61 70 70 65 64 4f 62 6a 65 63 74 } //1 set_WrappedObject
		$a_01_12 = {67 65 74 5f 43 75 6c 74 75 72 65 } //1 get_Culture
		$a_01_13 = {73 65 74 5f 43 75 6c 74 75 72 65 } //1 set_Culture
		$a_01_14 = {4e 65 77 4c 61 74 65 42 69 6e 64 69 6e 67 } //1 NewLateBinding
		$a_01_15 = {67 65 74 5f 58 } //1 get_X
		$a_01_16 = {67 65 74 5f 59 } //1 get_Y
		$a_01_17 = {43 72 65 61 74 65 48 61 6e 64 6c 65 } //1 CreateHandle
		$a_01_18 = {49 00 6e 00 76 00 6f 00 6b 00 65 00 } //1 Invoke
		$a_01_19 = {2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 .Resources
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1+(#a_01_17  & 1)*1+(#a_01_18  & 1)*1+(#a_01_19  & 1)*1) >=20
 
}
rule VirTool_BAT_Lore_MTB_22{
	meta:
		description = "VirTool:BAT/Lore!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 16 00 00 "
		
	strings :
		$a_01_0 = {3c 4d 6f 64 75 6c 65 3e } //1 <Module>
		$a_01_1 = {4c 69 67 68 74 } //1 Light
		$a_01_2 = {54 68 72 65 61 64 50 6f 6f 6c } //1 ThreadPool
		$a_01_3 = {76 61 72 31 } //1 var1
		$a_01_4 = {76 61 72 32 } //1 var2
		$a_01_5 = {76 61 72 33 } //1 var3
		$a_01_6 = {53 79 73 74 65 6d 2e 44 72 61 77 69 6e 67 } //1 System.Drawing
		$a_01_7 = {70 72 6f 6a 6e 61 6d 65 } //1 projname
		$a_01_8 = {47 75 72 75 } //1 Guru
		$a_01_9 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //1 DebuggerHiddenAttribute
		$a_01_10 = {44 65 62 75 67 67 65 72 53 74 65 70 54 68 72 6f 75 67 68 41 74 74 72 69 62 75 74 65 } //1 DebuggerStepThroughAttribute
		$a_01_11 = {41 63 74 69 76 61 74 6f 72 } //1 Activator
		$a_01_12 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_13 = {43 61 6c 6c 42 79 4e 61 6d 65 } //1 CallByName
		$a_01_14 = {53 79 73 74 65 6d 2e 54 68 72 65 61 64 69 6e 67 } //1 System.Threading
		$a_01_15 = {67 65 74 5f 52 } //1 get_R
		$a_01_16 = {67 65 74 5f 47 } //1 get_G
		$a_01_17 = {67 65 74 5f 42 } //1 get_B
		$a_01_18 = {4e 65 77 4c 61 74 65 42 69 6e 64 69 6e 67 } //1 NewLateBinding
		$a_01_19 = {4c 61 74 65 43 61 6c 6c } //1 LateCall
		$a_01_20 = {47 65 74 50 69 78 65 6c } //1 GetPixel
		$a_01_21 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1+(#a_01_17  & 1)*1+(#a_01_18  & 1)*1+(#a_01_19  & 1)*1+(#a_01_20  & 1)*1+(#a_01_21  & 1)*1) >=22
 
}
rule VirTool_BAT_Lore_MTB_23{
	meta:
		description = "VirTool:BAT/Lore!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 14 00 00 "
		
	strings :
		$a_01_0 = {76 61 72 31 } //1 var1
		$a_01_1 = {76 61 72 32 } //1 var2
		$a_01_2 = {76 61 72 33 } //1 var3
		$a_01_3 = {53 79 73 74 65 6d 2e 44 72 61 77 69 6e 67 } //1 System.Drawing
		$a_01_4 = {67 65 74 5f 57 69 64 74 68 } //1 get_Width
		$a_01_5 = {67 65 74 5f 4c 65 6e 67 74 68 } //1 get_Length
		$a_01_6 = {47 65 74 4d 61 6e 69 66 65 73 74 52 65 73 6f 75 72 63 65 53 74 72 65 61 6d } //1 GetManifestResourceStream
		$a_01_7 = {73 63 68 65 6d 61 66 69 6c 65 } //1 schemafile
		$a_01_8 = {4c 6f 61 64 46 69 6c 65 } //1 LoadFile
		$a_01_9 = {66 69 6c 65 } //1 file
		$a_01_10 = {4c 6f 61 64 53 74 72 65 61 6d } //1 LoadStream
		$a_01_11 = {73 74 72 65 61 6d } //1 stream
		$a_01_12 = {53 79 73 74 65 6d 2e 54 68 72 65 61 64 69 6e 67 } //1 System.Threading
		$a_01_13 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_14 = {53 79 73 74 65 6d 2e 52 65 66 6c 65 63 74 69 6f 6e } //1 System.Reflection
		$a_01_15 = {53 65 6c 65 63 74 6f 72 58 } //1 SelectorX
		$a_01_16 = {70 72 6f 6a 65 63 74 6e 61 6d 65 } //1 projectname
		$a_01_17 = {67 65 74 5f 57 72 61 70 70 65 64 4f 62 6a 65 63 74 } //1 get_WrappedObject
		$a_01_18 = {73 65 74 5f 57 72 61 70 70 65 64 4f 62 6a 65 63 74 } //1 set_WrappedObject
		$a_01_19 = {53 79 73 74 65 6d 2e 52 65 66 6c 65 63 74 69 6f 6e 2e 45 6d 69 74 } //1 System.Reflection.Emit
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1+(#a_01_17  & 1)*1+(#a_01_18  & 1)*1+(#a_01_19  & 1)*1) >=20
 
}
rule VirTool_BAT_Lore_MTB_24{
	meta:
		description = "VirTool:BAT/Lore!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 15 00 00 "
		
	strings :
		$a_01_0 = {3c 4d 6f 64 75 6c 65 3e } //1 <Module>
		$a_01_1 = {53 79 73 74 65 6d 2e 44 72 61 77 69 6e 67 } //1 System.Drawing
		$a_01_2 = {67 65 74 5f 4c 65 6e 67 74 68 } //1 get_Length
		$a_01_3 = {67 65 74 5f 57 69 64 74 68 } //1 get_Width
		$a_01_4 = {67 65 74 5f 48 65 69 67 68 74 } //1 get_Height
		$a_01_5 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //1 GetExecutingAssembly
		$a_01_6 = {67 65 74 5f 45 6e 74 72 79 50 6f 69 6e 74 } //1 get_EntryPoint
		$a_01_7 = {49 6e 76 6f 6b 65 } //1 Invoke
		$a_01_8 = {42 69 74 6d 61 70 } //1 Bitmap
		$a_01_9 = {47 65 74 50 69 78 65 6c } //1 GetPixel
		$a_01_10 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_11 = {70 72 6f 6a 65 63 74 5f 6e 61 6d 65 } //1 project_name
		$a_01_12 = {53 79 73 74 65 6d 2e 52 65 66 6c 65 63 74 69 6f 6e 2e 45 6d 69 74 } //1 System.Reflection.Emit
		$a_01_13 = {42 79 74 65 } //1 Byte
		$a_01_14 = {47 5a 69 70 53 74 72 65 61 6d } //1 GZipStream
		$a_01_15 = {53 79 73 74 65 6d 2e 49 4f 2e 43 6f 6d 70 72 65 73 73 69 6f 6e } //1 System.IO.Compression
		$a_01_16 = {43 6f 6d 70 72 65 73 73 69 6f 6e 4d 6f 64 65 } //1 CompressionMode
		$a_01_17 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //1 MemoryStream
		$a_01_18 = {67 65 74 5f 52 } //1 get_R
		$a_01_19 = {67 65 74 5f 47 } //1 get_G
		$a_01_20 = {67 65 74 5f 42 } //1 get_B
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1+(#a_01_17  & 1)*1+(#a_01_18  & 1)*1+(#a_01_19  & 1)*1+(#a_01_20  & 1)*1) >=21
 
}
rule VirTool_BAT_Lore_MTB_25{
	meta:
		description = "VirTool:BAT/Lore!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 16 00 00 "
		
	strings :
		$a_01_0 = {3c 4d 6f 64 75 6c 65 3e } //1 <Module>
		$a_01_1 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //1 MemoryStream
		$a_01_2 = {53 79 73 74 65 6d 2e 49 4f } //1 System.IO
		$a_01_3 = {47 5a 69 70 53 74 72 65 61 6d } //1 GZipStream
		$a_01_4 = {53 79 73 74 65 6d 2e 49 4f 2e 43 6f 6d 70 72 65 73 73 69 6f 6e } //1 System.IO.Compression
		$a_01_5 = {44 65 63 6f 6d 70 72 65 73 73 } //1 Decompress
		$a_01_6 = {45 6e 63 6f 64 69 6e 67 } //1 Encoding
		$a_01_7 = {52 65 73 69 7a 65 } //1 Resize
		$a_01_8 = {58 4f 52 5f 44 65 63 72 79 70 74 } //1 XOR_Decrypt
		$a_01_9 = {42 69 74 6d 61 70 } //1 Bitmap
		$a_01_10 = {53 79 73 74 65 6d 2e 52 65 73 6f 75 72 63 65 73 } //1 System.Resources
		$a_01_11 = {52 65 73 6f 75 72 63 65 5f 46 75 6e 63 } //1 Resource_Func
		$a_01_12 = {52 65 73 6f 75 72 63 65 4d 61 6e 61 67 65 72 } //1 ResourceManager
		$a_01_13 = {49 6e 76 6f 6b 65 } //1 Invoke
		$a_01_14 = {53 74 61 72 74 47 61 6d 65 } //1 StartGame
		$a_01_15 = {72 65 73 6f 75 72 63 65 5f 6e 61 6d 65 } //1 resource_name
		$a_01_16 = {6b 65 79 5f 70 61 72 61 6d } //1 key_param
		$a_01_17 = {70 72 6f 6a 65 63 74 5f 6e 61 6d 65 } //1 project_name
		$a_01_18 = {67 65 74 5f 57 69 64 74 68 } //1 get_Width
		$a_01_19 = {67 65 74 5f 48 65 69 67 68 74 } //1 get_Height
		$a_01_20 = {67 65 74 5f 45 6e 74 72 79 50 6f 69 6e 74 } //1 get_EntryPoint
		$a_01_21 = {53 79 73 74 65 6d 2e 54 68 72 65 61 64 69 6e 67 } //1 System.Threading
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1+(#a_01_17  & 1)*1+(#a_01_18  & 1)*1+(#a_01_19  & 1)*1+(#a_01_20  & 1)*1+(#a_01_21  & 1)*1) >=21
 
}
rule VirTool_BAT_Lore_MTB_26{
	meta:
		description = "VirTool:BAT/Lore!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 15 00 00 "
		
	strings :
		$a_01_0 = {76 61 72 31 } //1 var1
		$a_01_1 = {76 61 72 32 } //1 var2
		$a_01_2 = {76 61 72 33 } //1 var3
		$a_01_3 = {53 79 73 74 65 6d 2e 44 72 61 77 69 6e 67 } //1 System.Drawing
		$a_01_4 = {47 65 6e 65 72 61 74 65 64 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 GeneratedCodeAttribute
		$a_01_5 = {67 65 74 5f 56 61 6c 75 65 } //1 get_Value
		$a_01_6 = {73 65 74 5f 56 61 6c 75 65 } //1 set_Value
		$a_01_7 = {53 79 73 74 65 6d 2e 52 65 66 6c 65 63 74 69 6f 6e } //1 System.Reflection
		$a_01_8 = {47 65 74 4d 61 6e 69 66 65 73 74 52 65 73 6f 75 72 63 65 4e 61 6d 65 73 } //1 GetManifestResourceNames
		$a_01_9 = {4d 61 72 73 68 61 6c 42 79 52 65 66 4f 62 6a 65 63 74 } //1 MarshalByRefObject
		$a_01_10 = {44 65 66 6c 61 74 65 53 74 72 65 61 6d } //1 DeflateStream
		$a_01_11 = {53 79 73 74 65 6d 2e 53 65 63 75 72 69 74 79 2e 50 6f 6c 69 63 79 } //1 System.Security.Policy
		$a_01_12 = {43 6f 6e 74 61 69 6e 73 4b 65 79 } //1 ContainsKey
		$a_01_13 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //1 get_CurrentDomain
		$a_01_14 = {53 79 73 74 65 6d 2e 54 68 72 65 61 64 69 6e 67 } //1 System.Threading
		$a_01_15 = {67 65 74 5f 4c 65 6e 67 74 68 } //1 get_Length
		$a_01_16 = {67 65 74 5f 57 69 64 74 68 } //1 get_Width
		$a_01_17 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //1 GetExecutingAssembly
		$a_01_18 = {67 65 74 5f 57 72 61 70 70 65 64 4f 62 6a 65 63 74 } //1 get_WrappedObject
		$a_01_19 = {73 65 74 5f 57 72 61 70 70 65 64 4f 62 6a 65 63 74 } //1 set_WrappedObject
		$a_01_20 = {70 72 6f 6a 65 63 74 6e 61 6d 65 } //1 projectname
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1+(#a_01_17  & 1)*1+(#a_01_18  & 1)*1+(#a_01_19  & 1)*1+(#a_01_20  & 1)*1) >=21
 
}
rule VirTool_BAT_Lore_MTB_27{
	meta:
		description = "VirTool:BAT/Lore!MTB,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 17 00 00 "
		
	strings :
		$a_01_0 = {53 6f 61 70 4e 61 6d 65 2e 64 6c 6c } //1 SoapName.dll
		$a_01_1 = {53 79 73 74 65 6d 2e 52 75 6e 74 69 6d 65 2e 43 6f 6d 70 69 6c 65 72 53 65 72 76 69 63 65 73 } //1 System.Runtime.CompilerServices
		$a_01_2 = {53 79 73 74 65 6d 2e 52 75 6e 74 69 6d 65 2e 49 6e 74 65 72 6f 70 53 65 72 76 69 63 65 73 } //1 System.Runtime.InteropServices
		$a_01_3 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //1 DebuggerHiddenAttribute
		$a_01_4 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
		$a_01_5 = {42 69 74 6d 61 70 } //1 Bitmap
		$a_01_6 = {53 79 73 74 65 6d 2e 44 72 61 77 69 6e 67 } //1 System.Drawing
		$a_01_7 = {53 79 73 74 65 6d 2e 54 68 72 65 61 64 69 6e 67 } //1 System.Threading
		$a_01_8 = {67 65 74 5f 4c 65 6e 67 74 68 } //1 get_Length
		$a_01_9 = {67 65 74 5f 53 69 7a 65 } //1 get_Size
		$a_01_10 = {67 65 74 5f 57 69 64 74 68 } //1 get_Width
		$a_01_11 = {67 65 74 5f 43 6f 6d 70 75 74 65 72 } //1 get_Computer
		$a_01_12 = {67 65 74 5f 41 70 70 6c 69 63 61 74 69 6f 6e } //1 get_Application
		$a_01_13 = {67 65 74 5f 55 73 65 72 } //1 get_User
		$a_01_14 = {67 65 74 5f 57 65 62 53 65 72 76 69 63 65 73 } //1 get_WebServices
		$a_01_15 = {67 65 74 5f 52 65 73 6f 75 72 63 65 4d 61 6e 61 67 65 72 } //1 get_ResourceManager
		$a_01_16 = {67 65 74 5f 43 75 6c 74 75 72 65 } //1 get_Culture
		$a_01_17 = {67 65 74 5f 57 72 61 70 70 65 64 4f 62 6a 65 63 74 } //1 get_WrappedObject
		$a_01_18 = {4d 79 2e 43 6f 6d 70 75 74 65 72 } //1 My.Computer
		$a_01_19 = {4d 79 2e 41 70 70 6c 69 63 61 74 69 6f 6e } //1 My.Application
		$a_01_20 = {4d 79 2e 55 73 65 72 } //1 My.User
		$a_01_21 = {4d 79 2e 57 65 62 53 65 72 76 69 63 65 73 } //1 My.WebServices
		$a_01_22 = {4d 79 2e 53 65 74 74 69 6e 67 73 } //1 My.Settings
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1+(#a_01_17  & 1)*1+(#a_01_18  & 1)*1+(#a_01_19  & 1)*1+(#a_01_20  & 1)*1+(#a_01_21  & 1)*1+(#a_01_22  & 1)*1) >=23
 
}
rule VirTool_BAT_Lore_MTB_28{
	meta:
		description = "VirTool:BAT/Lore!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1d 00 1d 00 1d 00 00 "
		
	strings :
		$a_01_0 = {3c 4d 6f 64 75 6c 65 3e } //1 <Module>
		$a_01_1 = {53 79 73 74 65 6d 2e 49 4f } //1 System.IO
		$a_01_2 = {49 6e 76 65 72 73 65 51 } //1 InverseQ
		$a_01_3 = {44 65 66 69 6e 65 4d 65 74 68 6f 64 } //1 DefineMethod
		$a_01_4 = {43 72 79 70 74 6f 53 74 72 65 61 6d 4d 6f 64 65 } //1 CryptoStreamMode
		$a_01_5 = {67 65 74 5f 42 69 67 45 6e 64 69 61 6e 55 6e 69 63 6f 64 65 } //1 get_BigEndianUnicode
		$a_01_6 = {73 65 74 5f 4e 61 6d 65 } //1 set_Name
		$a_01_7 = {41 73 73 65 6d 62 6c 79 4e 61 6d 65 } //1 AssemblyName
		$a_01_8 = {70 72 6f 6a 65 63 74 6e 61 6d 65 } //1 projectname
		$a_01_9 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_01_10 = {4f 62 66 75 73 63 61 74 69 6f 6e 41 74 74 72 69 62 75 74 65 } //1 ObfuscationAttribute
		$a_01_11 = {67 65 74 5f 53 69 7a 65 } //1 get_Size
		$a_01_12 = {53 79 73 74 65 6d 2e 54 68 72 65 61 64 69 6e 67 } //1 System.Threading
		$a_01_13 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_14 = {53 79 73 74 65 6d 2e 44 72 61 77 69 6e 67 } //1 System.Drawing
		$a_01_15 = {42 69 6e 61 72 79 53 65 61 72 63 68 } //1 BinarySearch
		$a_01_16 = {67 65 74 5f 57 69 64 74 68 } //1 get_Width
		$a_01_17 = {67 65 74 5f 4c 65 6e 67 74 68 } //1 get_Length
		$a_01_18 = {44 65 66 69 6e 65 4c 61 62 65 6c } //1 DefineLabel
		$a_01_19 = {47 65 74 50 69 78 65 6c } //1 GetPixel
		$a_01_20 = {47 65 74 4d 61 6e 69 66 65 73 74 52 65 73 6f 75 72 63 65 53 74 72 65 61 6d } //1 GetManifestResourceStream
		$a_01_21 = {43 72 79 70 74 6f 53 74 72 65 61 6d } //1 CryptoStream
		$a_01_22 = {41 70 70 44 6f 6d 61 69 6e } //1 AppDomain
		$a_01_23 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //1 get_CurrentDomain
		$a_01_24 = {42 69 74 6d 61 70 } //1 Bitmap
		$a_01_25 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_26 = {67 65 74 5f 4a 6f 6e 61 73 } //1 get_Jonas
		$a_01_27 = {73 65 74 5f 4a 6f 6e 61 73 } //1 set_Jonas
		$a_01_28 = {64 65 61 64 20 63 6f 64 65 54 } //1 dead codeT
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1+(#a_01_17  & 1)*1+(#a_01_18  & 1)*1+(#a_01_19  & 1)*1+(#a_01_20  & 1)*1+(#a_01_21  & 1)*1+(#a_01_22  & 1)*1+(#a_01_23  & 1)*1+(#a_01_24  & 1)*1+(#a_01_25  & 1)*1+(#a_01_26  & 1)*1+(#a_01_27  & 1)*1+(#a_01_28  & 1)*1) >=29
 
}
rule VirTool_BAT_Lore_MTB_29{
	meta:
		description = "VirTool:BAT/Lore!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1f 00 1f 00 00 "
		
	strings :
		$a_01_0 = {3c 4d 6f 64 75 6c 65 3e } //1 <Module>
		$a_01_1 = {46 65 74 63 68 55 70 64 61 74 65 } //1 FetchUpdate
		$a_01_2 = {53 74 61 72 74 55 70 64 61 74 65 } //1 StartUpdate
		$a_01_3 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_01_4 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_5 = {53 79 73 74 65 6d 2e 44 72 61 77 69 6e 67 } //1 System.Drawing
		$a_01_6 = {43 6f 6d 70 75 74 65 48 61 73 68 } //1 ComputeHash
		$a_01_7 = {67 65 74 5f 57 69 64 74 68 } //1 get_Width
		$a_01_8 = {67 65 74 5f 4c 65 6e 67 74 68 } //1 get_Length
		$a_01_9 = {47 65 74 50 69 78 65 6c } //1 GetPixel
		$a_01_10 = {47 65 74 4d 61 6e 69 66 65 73 74 52 65 73 6f 75 72 63 65 53 74 72 65 61 6d } //1 GetManifestResourceStream
		$a_01_11 = {67 65 74 5f 42 61 73 65 53 74 72 65 61 6d } //1 get_BaseStream
		$a_01_12 = {43 72 79 70 74 6f 53 74 72 65 61 6d } //1 CryptoStream
		$a_01_13 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //1 MemoryStream
		$a_01_14 = {41 70 70 44 6f 6d 61 69 6e } //1 AppDomain
		$a_01_15 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //1 get_CurrentDomain
		$a_01_16 = {73 65 74 5f 50 6f 73 69 74 69 6f 6e } //1 set_Position
		$a_01_17 = {49 6e 76 61 6c 69 64 4f 70 65 72 61 74 69 6f 6e 45 78 63 65 70 74 69 6f 6e } //1 InvalidOperationException
		$a_01_18 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
		$a_01_19 = {43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //1 CryptoServiceProvider
		$a_01_20 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_21 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
		$a_01_22 = {53 79 73 74 65 6d 2e 52 65 66 6c 65 63 74 69 6f 6e 2e 45 6d 69 74 } //1 System.Reflection.Emit
		$a_01_23 = {67 65 74 5f 45 6e 74 72 79 50 6f 69 6e 74 } //1 get_EntryPoint
		$a_01_24 = {73 65 74 5f 4b 65 79 } //1 set_Key
		$a_01_25 = {53 79 73 74 65 6d 2e 53 65 63 75 72 69 74 79 2e 43 72 79 70 74 6f 67 72 61 70 68 79 } //1 System.Security.Cryptography
		$a_01_26 = {67 65 74 5f 43 6f 72 65 50 72 6f 70 65 72 74 79 } //1 get_CoreProperty
		$a_01_27 = {73 65 74 5f 43 6f 72 65 50 72 6f 70 65 72 74 79 } //1 set_CoreProperty
		$a_81_28 = {54 53 50 32 55 57 55 47 66 30 55 58 4c 55 49 69 4f 58 41 66 42 6b 67 6c 52 42 74 6c 57 45 61 36 4c 45 35 6a 55 43 70 32 52 52 58 78 64 32 5a 35 54 6c 31 71 50 57 5a } //1 TSP2UWUGf0UXLUIiOXAfBkglRBtlWEa6LE5jUCp2RRXxd2Z5Tl1qPWZ
		$a_01_29 = {64 65 61 64 20 63 6f 64 65 54 } //1 dead codeT
		$a_01_30 = {53 74 72 69 70 41 66 74 65 72 4f 62 66 75 73 63 61 74 69 6f 6e } //1 StripAfterObfuscation
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1+(#a_01_17  & 1)*1+(#a_01_18  & 1)*1+(#a_01_19  & 1)*1+(#a_01_20  & 1)*1+(#a_01_21  & 1)*1+(#a_01_22  & 1)*1+(#a_01_23  & 1)*1+(#a_01_24  & 1)*1+(#a_01_25  & 1)*1+(#a_01_26  & 1)*1+(#a_01_27  & 1)*1+(#a_81_28  & 1)*1+(#a_01_29  & 1)*1+(#a_01_30  & 1)*1) >=31
 
}
rule VirTool_BAT_Lore_MTB_30{
	meta:
		description = "VirTool:BAT/Lore!MTB,SIGNATURE_TYPE_PEHSTR_EXT,65 00 65 00 14 00 00 "
		
	strings :
		$a_01_0 = {7b 00 31 00 31 00 31 00 31 00 31 00 2d 00 32 00 32 00 32 00 32 00 32 00 2d 00 31 00 30 00 30 00 30 00 39 00 2d 00 31 00 31 00 31 00 31 00 32 00 7d 00 } //1 {11111-22222-10009-11112}
		$a_01_1 = {7b 00 31 00 31 00 31 00 31 00 31 00 2d 00 32 00 32 00 32 00 32 00 32 00 2d 00 35 00 30 00 30 00 30 00 31 00 2d 00 30 00 30 00 30 00 30 00 30 00 7d 00 } //1 {11111-22222-50001-00000}
		$a_01_2 = {7b 00 31 00 31 00 31 00 31 00 31 00 2d 00 32 00 32 00 32 00 32 00 32 00 2d 00 32 00 30 00 30 00 30 00 31 00 2d 00 30 00 30 00 30 00 30 00 31 00 7d 00 } //1 {11111-22222-20001-00001}
		$a_01_3 = {7b 00 31 00 31 00 31 00 31 00 31 00 2d 00 32 00 32 00 32 00 32 00 32 00 2d 00 32 00 30 00 30 00 30 00 31 00 2d 00 30 00 30 00 30 00 30 00 32 00 7d 00 } //1 {11111-22222-20001-00002}
		$a_01_4 = {7b 00 31 00 31 00 31 00 31 00 31 00 2d 00 32 00 32 00 32 00 32 00 32 00 2d 00 33 00 30 00 30 00 30 00 31 00 2d 00 30 00 30 00 30 00 30 00 31 00 7d 00 } //1 {11111-22222-30001-00001}
		$a_01_5 = {7b 00 31 00 31 00 31 00 31 00 31 00 2d 00 32 00 32 00 32 00 32 00 32 00 2d 00 33 00 30 00 30 00 30 00 31 00 2d 00 30 00 30 00 30 00 30 00 32 00 7d 00 } //1 {11111-22222-30001-00002}
		$a_01_6 = {7b 00 31 00 31 00 31 00 31 00 31 00 2d 00 32 00 32 00 32 00 32 00 32 00 2d 00 34 00 30 00 30 00 30 00 31 00 2d 00 30 00 30 00 30 00 30 00 31 00 7d 00 } //1 {11111-22222-40001-00001}
		$a_01_7 = {7b 00 31 00 31 00 31 00 31 00 31 00 2d 00 32 00 32 00 32 00 32 00 32 00 2d 00 34 00 30 00 30 00 30 00 31 00 2d 00 30 00 30 00 30 00 30 00 32 00 7d 00 } //1 {11111-22222-40001-00002}
		$a_01_8 = {7b 00 31 00 31 00 31 00 31 00 31 00 2d 00 32 00 32 00 32 00 32 00 32 00 2d 00 35 00 30 00 30 00 30 00 31 00 2d 00 30 00 30 00 30 00 30 00 31 00 7d 00 } //1 {11111-22222-50001-00001}
		$a_01_9 = {7b 00 31 00 31 00 31 00 31 00 31 00 2d 00 32 00 32 00 32 00 32 00 32 00 2d 00 35 00 30 00 30 00 30 00 31 00 2d 00 30 00 30 00 30 00 30 00 32 00 7d 00 } //1 {11111-22222-50001-00002}
		$a_01_10 = {66 00 69 00 6c 00 65 00 3a 00 2f 00 2f 00 2f 00 } //10 file:///
		$a_01_11 = {64 65 61 64 20 63 6f 64 65 54 } //10 dead codeT
		$a_01_12 = {53 74 72 69 70 41 66 74 65 72 4f 62 66 75 73 63 61 74 69 6f 6e } //10 StripAfterObfuscation
		$a_01_13 = {6d 5f 75 73 65 55 73 65 72 4f 76 65 72 72 69 64 65 } //10 m_useUserOverride
		$a_01_14 = {43 72 65 61 74 65 45 6e 63 72 79 70 74 6f 72 } //10 CreateEncryptor
		$a_01_15 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //10 ToBase64String
		$a_01_16 = {43 69 70 68 65 72 4d 6f 64 65 } //10 CipherMode
		$a_01_17 = {73 65 74 5f 4d 6f 64 65 } //10 set_Mode
		$a_01_18 = {73 65 74 5f 55 73 65 4d 61 63 68 69 6e 65 4b 65 79 53 74 6f 72 65 } //10 set_UseMachineKeyStore
		$a_01_19 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //10 CreateDecryptor
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*10+(#a_01_11  & 1)*10+(#a_01_12  & 1)*10+(#a_01_13  & 1)*10+(#a_01_14  & 1)*10+(#a_01_15  & 1)*10+(#a_01_16  & 1)*10+(#a_01_17  & 1)*10+(#a_01_18  & 1)*10+(#a_01_19  & 1)*10) >=101
 
}