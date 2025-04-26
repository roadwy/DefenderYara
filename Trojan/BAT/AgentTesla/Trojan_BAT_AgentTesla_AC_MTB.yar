
rule Trojan_BAT_AgentTesla_AC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {20 00 01 00 00 13 08 11 07 17 58 13 09 11 07 20 00 56 01 00 5d 13 0a 11 09 20 00 56 01 00 5d 13 0b 07 11 0b 91 11 08 58 13 0c 07 11 0a 91 13 0d 08 11 07 1f 16 5d 91 13 0e 11 0d 11 0e 61 13 0f 07 11 0a 11 0f 11 0c 59 11 08 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_AgentTesla_AC_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {19 9a 20 0c 07 00 00 95 5f 7e 06 00 00 04 19 9a 20 86 08 00 00 95 61 59 81 07 00 00 01 7e 06 00 00 04 17 9a 1f 10 95 } //4
		$a_01_1 = {2d 03 16 2b 01 17 17 59 7e 2c 00 00 04 20 53 02 00 00 95 5f 7e 2c 00 00 04 20 8b 01 00 00 95 61 58 81 07 00 00 01 } //4
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*4) >=4
 
}
rule Trojan_BAT_AgentTesla_AC_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_81_0 = {43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 53 68 65 6c 6c 20 46 6f 6c 64 65 72 73 } //3 CurrentVersion\Explorer\Shell Folders
		$a_81_1 = {5c 41 75 64 69 6f 41 70 70 } //3 \AudioApp
		$a_81_2 = {2f 43 20 72 75 6e 64 } //3 /C rund
		$a_81_3 = {5c 44 6f 77 6e 6c 6f 61 64 73 5c } //3 \Downloads\
		$a_81_4 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 54 61 73 6b 41 73 79 6e 63 } //3 DownloadFileTaskAsync
		$a_81_5 = {4a 61 63 6b 2b 4d 79 41 64 64 49 6e 2b 3c 44 6f 77 6e 6c 6f 61 64 3e } //3 Jack+MyAddIn+<Download>
		$a_81_6 = {6a 61 7a 6b 2e 64 6c 6c } //3 jazk.dll
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3+(#a_81_4  & 1)*3+(#a_81_5  & 1)*3+(#a_81_6  & 1)*3) >=21
 
}
rule Trojan_BAT_AgentTesla_AC_MTB_4{
	meta:
		description = "Trojan:BAT/AgentTesla.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_00_0 = {57 95 a2 29 09 1f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 9e 00 00 00 1a 00 00 00 a4 00 00 00 59 01 } //3
		$a_81_1 = {44 6f 63 6b 53 74 79 6c 65 } //3 DockStyle
		$a_81_2 = {40 70 6b 52 65 6d 69 6e 64 65 72 } //3 @pkReminder
		$a_81_3 = {45 78 65 63 75 74 65 4e 6f 6e 51 75 65 72 79 } //3 ExecuteNonQuery
		$a_81_4 = {5b 70 6f 6c 64 61 74 61 35 5d 2e 5b 44 65 6c 65 74 65 45 78 69 73 74 69 6e 67 52 65 6d 69 6e 64 65 72 5d } //3 [poldata5].[DeleteExistingReminder]
		$a_81_5 = {40 44 61 74 75 6d } //3 @Datum
		$a_81_6 = {70 6f 6c 64 61 74 61 35 2e 55 70 64 61 74 65 53 6e 6f 6f 7a 65 } //3 poldata5.UpdateSnooze
	condition:
		((#a_00_0  & 1)*3+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3+(#a_81_4  & 1)*3+(#a_81_5  & 1)*3+(#a_81_6  & 1)*3) >=21
 
}
rule Trojan_BAT_AgentTesla_AC_MTB_5{
	meta:
		description = "Trojan:BAT/AgentTesla.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 12 00 08 00 00 "
		
	strings :
		$a_02_0 = {0a 1e 9a 0c 19 8d ?? ?? ?? 01 25 16 72 ?? ?? ?? 70 a2 25 17 7e ?? ?? ?? 04 a2 25 18 7e ?? ?? ?? 04 a2 0d 09 28 ?? ?? ?? 0a 00 08 09 28 ?? ?? ?? 0a 26 20 ?? ?? ?? 00 0a 2b 00 06 2a } //10
		$a_80_1 = {46 61 6c 6c 62 61 63 6b 42 75 66 66 65 72 } //FallbackBuffer  4
		$a_80_2 = {57 53 54 52 42 75 66 66 65 72 4d 61 72 73 68 61 6c 65 72 } //WSTRBufferMarshaler  4
		$a_80_3 = {44 73 6b 45 78 70 6c 6f 72 65 72 } //DskExplorer  4
		$a_80_4 = {49 64 65 6e 74 69 74 79 41 75 74 68 6f 72 69 74 79 } //IdentityAuthority  3
		$a_80_5 = {45 78 63 6c 75 73 69 76 65 53 63 68 65 64 75 6c 65 72 } //ExclusiveScheduler  3
		$a_80_6 = {44 65 73 45 6e 63 72 69 70 74 49 74 } //DesEncriptIt  2
		$a_80_7 = {45 6e 63 72 69 70 74 49 74 } //EncriptIt  2
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*4+(#a_80_2  & 1)*4+(#a_80_3  & 1)*4+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*2+(#a_80_7  & 1)*2) >=18
 
}