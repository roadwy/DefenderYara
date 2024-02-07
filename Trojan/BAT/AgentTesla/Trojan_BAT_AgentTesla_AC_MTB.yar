
rule Trojan_BAT_AgentTesla_AC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 04 00 "
		
	strings :
		$a_01_0 = {19 9a 20 0c 07 00 00 95 5f 7e 06 00 00 04 19 9a 20 86 08 00 00 95 61 59 81 07 00 00 01 7e 06 00 00 04 17 9a 1f 10 95 } //04 00 
		$a_01_1 = {2d 03 16 2b 01 17 17 59 7e 2c 00 00 04 20 53 02 00 00 95 5f 7e 2c 00 00 04 20 8b 01 00 00 95 61 58 81 07 00 00 01 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_AC_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 03 00 "
		
	strings :
		$a_81_0 = {43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 53 68 65 6c 6c 20 46 6f 6c 64 65 72 73 } //03 00  CurrentVersion\Explorer\Shell Folders
		$a_81_1 = {5c 41 75 64 69 6f 41 70 70 } //03 00  \AudioApp
		$a_81_2 = {2f 43 20 72 75 6e 64 } //03 00  /C rund
		$a_81_3 = {5c 44 6f 77 6e 6c 6f 61 64 73 5c } //03 00  \Downloads\
		$a_81_4 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 54 61 73 6b 41 73 79 6e 63 } //03 00  DownloadFileTaskAsync
		$a_81_5 = {4a 61 63 6b 2b 4d 79 41 64 64 49 6e 2b 3c 44 6f 77 6e 6c 6f 61 64 3e } //03 00  Jack+MyAddIn+<Download>
		$a_81_6 = {6a 61 7a 6b 2e 64 6c 6c } //00 00  jazk.dll
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_AC_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 03 00 "
		
	strings :
		$a_00_0 = {57 95 a2 29 09 1f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 9e 00 00 00 1a 00 00 00 a4 00 00 00 59 01 } //03 00 
		$a_81_1 = {44 6f 63 6b 53 74 79 6c 65 } //03 00  DockStyle
		$a_81_2 = {40 70 6b 52 65 6d 69 6e 64 65 72 } //03 00  @pkReminder
		$a_81_3 = {45 78 65 63 75 74 65 4e 6f 6e 51 75 65 72 79 } //03 00  ExecuteNonQuery
		$a_81_4 = {5b 70 6f 6c 64 61 74 61 35 5d 2e 5b 44 65 6c 65 74 65 45 78 69 73 74 69 6e 67 52 65 6d 69 6e 64 65 72 5d } //03 00  [poldata5].[DeleteExistingReminder]
		$a_81_5 = {40 44 61 74 75 6d } //03 00  @Datum
		$a_81_6 = {70 6f 6c 64 61 74 61 35 2e 55 70 64 61 74 65 53 6e 6f 6f 7a 65 } //00 00  poldata5.UpdateSnooze
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_AC_MTB_4{
	meta:
		description = "Trojan:BAT/AgentTesla.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 12 00 08 00 00 0a 00 "
		
	strings :
		$a_02_0 = {0a 1e 9a 0c 19 8d 90 01 03 01 25 16 72 90 01 03 70 a2 25 17 7e 90 01 03 04 a2 25 18 7e 90 01 03 04 a2 0d 09 28 90 01 03 0a 00 08 09 28 90 01 03 0a 26 20 90 01 03 00 0a 2b 00 06 2a 90 00 } //04 00 
		$a_80_1 = {46 61 6c 6c 62 61 63 6b 42 75 66 66 65 72 } //FallbackBuffer  04 00 
		$a_80_2 = {57 53 54 52 42 75 66 66 65 72 4d 61 72 73 68 61 6c 65 72 } //WSTRBufferMarshaler  04 00 
		$a_80_3 = {44 73 6b 45 78 70 6c 6f 72 65 72 } //DskExplorer  03 00 
		$a_80_4 = {49 64 65 6e 74 69 74 79 41 75 74 68 6f 72 69 74 79 } //IdentityAuthority  03 00 
		$a_80_5 = {45 78 63 6c 75 73 69 76 65 53 63 68 65 64 75 6c 65 72 } //ExclusiveScheduler  02 00 
		$a_80_6 = {44 65 73 45 6e 63 72 69 70 74 49 74 } //DesEncriptIt  02 00 
		$a_80_7 = {45 6e 63 72 69 70 74 49 74 } //EncriptIt  00 00 
	condition:
		any of ($a_*)
 
}