
rule Trojan_BAT_AgentTesla_EM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_03_0 = {0c 06 8e 69 17 59 0d 2b 1a 08 06 09 9a 07 09 8f ?? ?? ?? 01 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 0c 09 17 59 0d 09 16 2f e2 } //10
		$a_81_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_2 = {41 63 74 69 76 61 74 6f 72 } //1 Activator
		$a_81_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_4 = {52 65 70 6c 61 63 65 } //1 Replace
	condition:
		((#a_03_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=14
 
}
rule Trojan_BAT_AgentTesla_EM_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {4d 4f 48 42 41 44 2e 4d 4f 48 42 41 44 } //1 MOHBAD.MOHBAD
		$a_81_1 = {62 61 64 62 61 64 6d 6f 68 68 2e 74 78 74 } //1 badbadmohh.txt
		$a_81_2 = {4b 59 4f 2d 54 55 58 2d 47 49 4e 55 58 2d 46 49 4c 45 2d 54 59 50 45 53 2d 4a 50 45 47 } //1 KYO-TUX-GINUX-FILE-TYPES-JPEG
		$a_81_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_4 = {73 65 74 5f 53 65 63 75 72 69 74 79 50 72 6f 74 6f 63 6f 6c } //1 set_SecurityProtocol
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}
rule Trojan_BAT_AgentTesla_EM_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {08 1b 62 08 58 11 04 61 0c 11 05 18 58 49 13 04 11 04 39 1d 00 00 00 09 1b 62 09 58 11 04 61 0d 11 05 18 d3 18 5a 58 13 05 11 05 49 25 13 04 } //5
		$a_01_1 = {70 00 4e 00 70 00 46 00 6e 00 56 00 39 00 5a 00 6e 00 57 00 52 00 32 00 55 00 48 00 51 00 46 00 67 00 67 00 2e 00 4c 00 71 00 6b 00 72 00 42 00 53 00 41 00 61 00 52 00 45 00 76 00 34 00 64 00 35 00 45 00 38 00 6c 00 77 00 } //1 pNpFnV9ZnWR2UHQFgg.LqkrBSAaREv4d5E8lw
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}
rule Trojan_BAT_AgentTesla_EM_MTB_4{
	meta:
		description = "Trojan:BAT/AgentTesla.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 00 73 00 68 00 4e 00 65 00 74 00 53 00 77 00 69 00 74 00 63 00 68 00 } //1 SshNetSwitch
		$a_01_1 = {53 00 73 00 68 00 4e 00 65 00 74 00 2e 00 4c 00 6f 00 67 00 67 00 69 00 6e 00 67 00 } //1 SshNet.Logging
		$a_01_2 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 31 00 39 00 32 00 2e 00 33 00 2e 00 32 00 31 00 35 00 2e 00 36 00 30 00 } //1 http://192.3.215.60
		$a_01_3 = {53 00 68 00 65 00 6c 00 6c 00 20 00 69 00 73 00 20 00 73 00 74 00 61 00 72 00 74 00 65 00 64 00 } //1 Shell is started
		$a_01_4 = {48 74 74 70 52 65 73 70 6f 6e 73 65 4d 65 73 73 61 67 65 } //1 HttpResponseMessage
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_BAT_AgentTesla_EM_MTB_5{
	meta:
		description = "Trojan:BAT/AgentTesla.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 "
		
	strings :
		$a_00_0 = {01 57 17 02 08 09 01 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 2f 00 00 00 07 00 00 00 05 00 00 00 10 } //3
		$a_81_1 = {53 65 63 75 72 69 74 79 50 72 6f 74 6f 63 6f 6c 54 79 70 65 } //3 SecurityProtocolType
		$a_81_2 = {64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d 2f 61 74 74 61 63 68 6d 65 6e 74 73 } //3 discordapp.com/attachments
		$a_81_3 = {47 65 74 52 65 73 70 6f 6e 73 65 53 74 72 65 61 6d } //3 GetResponseStream
		$a_81_4 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //3 get_CurrentDomain
		$a_81_5 = {73 65 74 5f 53 65 63 75 72 69 74 79 50 72 6f 74 6f 63 6f 6c } //3 set_SecurityProtocol
	condition:
		((#a_00_0  & 1)*3+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3+(#a_81_4  & 1)*3+(#a_81_5  & 1)*3) >=18
 
}
rule Trojan_BAT_AgentTesla_EM_MTB_6{
	meta:
		description = "Trojan:BAT/AgentTesla.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {55 73 65 53 79 73 74 65 6d 50 61 73 73 77 6f 72 64 43 68 61 72 } //1 UseSystemPasswordChar
		$a_01_1 = {31 6d 76 79 48 44 51 54 74 6c 36 4c 62 7a 6c 34 44 4c 55 43 51 79 56 37 6f 6a 66 57 46 4a 6f 41 55 4c 51 47 68 63 52 41 41 30 42 } //1 1mvyHDQTtl6Lbzl4DLUCQyV7ojfWFJoAULQGhcRAA0B
		$a_01_2 = {6f 68 65 6e 61 64 6f 66 69 6d 6f 74 75 6b 69 66 75 79 61 6b 61 71 } //1 ohenadofimotukifuyakaq
		$a_01_3 = {41 43 47 4e 6f 47 55 68 61 4f 45 52 78 66 42 45 55 6e 75 37 61 51 61 6f 48 70 48 65 } //1 ACGNoGUhaOERxfBEUnu7aQaoHpHe
		$a_01_4 = {43 71 46 65 4b 72 74 4e 48 69 70 66 6f 39 78 52 65 4a 71 78 4a 67 35 6e 39 53 45 57 67 42 33 32 66 50 } //1 CqFeKrtNHipfo9xReJqxJg5n9SEWgB32fP
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_BAT_AgentTesla_EM_MTB_7{
	meta:
		description = "Trojan:BAT/AgentTesla.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {35 00 36 00 37 00 33 00 32 00 37 00 66 00 36 00 2d 00 38 00 37 00 66 00 30 00 2d 00 34 00 32 00 66 00 30 00 2d 00 39 00 61 00 62 00 36 00 2d 00 35 00 63 00 31 00 64 00 31 00 64 00 65 00 66 00 31 00 38 00 34 00 32 00 2e 00 65 00 78 00 65 00 } //1 567327f6-87f0-42f0-9ab6-5c1d1def1842.exe
		$a_01_1 = {67 65 74 5f 47 75 69 64 4d 61 73 74 65 72 4b 65 79 } //1 get_GuidMasterKey
		$a_01_2 = {53 65 72 69 61 6c 69 7a 61 74 69 6f 6e 2e 46 6f 72 6d 61 74 74 65 72 73 2e 42 69 6e 61 72 79 } //1 Serialization.Formatters.Binary
		$a_01_3 = {55 6e 61 62 6c 65 20 74 6f 20 72 65 73 6f 6c 76 65 20 48 54 54 50 20 70 72 6f 78 } //1 Unable to resolve HTTP prox
		$a_01_4 = {63 6f 6d 2e 61 70 70 6c 65 2e 53 61 66 61 72 69 } //1 com.apple.Safari
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_BAT_AgentTesla_EM_MTB_8{
	meta:
		description = "Trojan:BAT/AgentTesla.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_00_0 = {57 9f a2 29 09 0f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 be 00 00 00 33 00 00 00 7e 00 00 00 26 01 } //3
		$a_81_1 = {53 79 73 74 65 6d 2e 54 68 72 65 61 64 69 6e 67 2e 54 61 73 6b 73 } //3 System.Threading.Tasks
		$a_81_2 = {48 74 74 70 53 65 72 76 65 72 55 74 69 6c 69 74 79 } //3 HttpServerUtility
		$a_81_3 = {4b 65 79 56 61 6c 75 65 53 74 6f 72 65 2f 4d 61 73 74 65 72 } //3 KeyValueStore/Master
		$a_81_4 = {70 6c 61 79 65 72 42 69 6e 64 69 6e 67 53 6f 75 72 63 65 2e 54 72 61 79 4c 6f 63 61 74 69 6f 6e } //3 playerBindingSource.TrayLocation
		$a_81_5 = {48 35 46 47 4a 38 58 52 34 34 47 35 54 46 57 34 41 34 50 41 38 50 } //3 H5FGJ8XR44G5TFW4A4PA8P
		$a_81_6 = {41 69 72 63 72 61 66 74 20 52 69 67 } //3 Aircraft Rig
	condition:
		((#a_00_0  & 1)*3+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3+(#a_81_4  & 1)*3+(#a_81_5  & 1)*3+(#a_81_6  & 1)*3) >=21
 
}
rule Trojan_BAT_AgentTesla_EM_MTB_9{
	meta:
		description = "Trojan:BAT/AgentTesla.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_81_0 = {44 3a 5c 45 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 78 74 2e 74 78 74 } //3 D:\Effffffffffffffffffffffffffxt.txt
		$a_81_1 = {61 77 61 69 74 20 3d } //3 await =
		$a_81_2 = {44 3a 75 67 68 75 45 78 74 2e 74 78 74 } //3 D:ughuExt.txt
		$a_81_3 = {43 72 79 70 74 6f 4f 62 66 75 73 63 61 74 6f 72 2e 50 72 6f 74 65 63 74 65 64 57 69 74 68 43 72 79 70 74 6f 4f 62 66 75 73 63 61 74 6f 72 41 74 74 72 69 62 75 74 65 } //3 CryptoObfuscator.ProtectedWithCryptoObfuscatorAttribute
		$a_81_4 = {55 73 65 53 68 65 6c 6c 45 78 65 63 75 74 65 } //3 UseShellExecute
		$a_81_5 = {50 72 6f 63 65 73 73 65 64 42 79 58 65 6e 6f 63 6f 64 65 } //3 ProcessedByXenocode
		$a_81_6 = {45 64 66 69 6a 6b 69 30 6a 6f 69 66 66 66 66 66 66 66 66 66 78 74 2e 74 78 74 } //3 Edfijki0joifffffffffxt.txt
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3+(#a_81_4  & 1)*3+(#a_81_5  & 1)*3+(#a_81_6  & 1)*3) >=21
 
}
rule Trojan_BAT_AgentTesla_EM_MTB_10{
	meta:
		description = "Trojan:BAT/AgentTesla.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {58 00 58 00 53 00 58 00 79 00 58 00 73 00 58 00 74 00 58 00 65 00 58 00 6d 00 58 00 2e 00 58 00 52 00 58 00 65 00 58 00 58 00 58 00 66 00 58 00 58 00 6c 00 58 00 65 00 58 00 63 00 58 00 74 00 58 00 69 00 58 00 6f 00 58 00 6e 00 58 00 2e 00 58 00 41 00 58 00 73 00 58 00 73 00 58 00 65 00 58 00 6d 00 58 00 62 00 58 00 6c 00 58 00 79 00 58 00 58 00 } //1 XXSXyXsXtXeXmX.XRXeXXXfXXlXeXcXtXiXoXnX.XAXsXsXeXmXbXlXyXX
		$a_01_1 = {53 00 71 00 75 00 65 00 61 00 6c 00 65 00 72 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 Squealer.Resources
		$a_01_2 = {47 00 65 00 74 00 4d 00 61 00 6e 00 69 00 66 00 65 00 73 00 74 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 4e 00 61 00 6d 00 65 00 73 00 } //1 GetManifestResourceNames
		$a_01_3 = {53 6f 61 70 48 74 74 70 43 6c 69 65 6e 74 50 72 6f 74 6f 63 6f 6c } //1 SoapHttpClientProtocol
		$a_01_4 = {54 6f 6f 6c 73 2e 53 74 72 6f 6e 67 6c 79 54 79 70 65 64 52 65 73 6f 75 72 63 65 42 75 69 6c 64 65 72 } //1 Tools.StronglyTypedResourceBuilder
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_BAT_AgentTesla_EM_MTB_11{
	meta:
		description = "Trojan:BAT/AgentTesla.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,21 00 21 00 0c 00 00 "
		
	strings :
		$a_81_0 = {24 36 65 32 65 66 30 34 39 2d 36 66 62 30 2d 34 37 39 66 2d 61 33 34 36 2d 32 66 38 65 35 64 39 31 39 35 61 61 } //20 $6e2ef049-6fb0-479f-a346-2f8e5d9195aa
		$a_01_1 = {24 43 35 41 43 41 44 39 46 2d 46 34 42 34 2d 34 35 33 32 2d 38 35 38 35 2d 46 33 31 44 35 38 35 35 32 36 39 42 } //20 $C5ACAD9F-F4B4-4532-8585-F31D5855269B
		$a_81_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //5 CreateInstance
		$a_81_3 = {41 63 74 69 76 61 74 6f 72 } //5 Activator
		$a_81_4 = {41 6e 61 53 6f 66 74 56 65 72 4b 53 56 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 AnaSoftVerKSV.Resources.resources
		$a_81_5 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
		$a_81_6 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerBrowsableAttribute
		$a_81_7 = {44 65 62 75 67 67 65 72 53 74 65 70 54 68 72 6f 75 67 68 41 74 74 72 69 62 75 74 65 } //1 DebuggerStepThroughAttribute
		$a_81_8 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //1 DebuggerBrowsableState
		$a_81_9 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //1 DebuggerHiddenAttribute
		$a_81_10 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_81_11 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
	condition:
		((#a_81_0  & 1)*20+(#a_01_1  & 1)*20+(#a_81_2  & 1)*5+(#a_81_3  & 1)*5+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1) >=33
 
}