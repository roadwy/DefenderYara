
rule Trojan_Win64_Sdum_RM_MTB{
	meta:
		description = "Trojan:Win64/Sdum.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {69 6e 66 69 6e 69 74 79 63 68 65 61 74 73 5c 47 61 6d 65 48 65 6c 70 65 72 73 4c 6f 61 64 65 72 5f 5f 41 50 45 58 5f 54 4d 48 5c 47 61 6d 65 48 65 6c 70 65 72 73 4c 6f 61 64 65 72 5f 5f 41 50 45 58 5f 54 4d 48 5c 62 69 6e 5c 52 65 6c 65 61 73 65 5c 6e 65 74 38 2e 30 2d 77 69 6e 64 6f 77 73 5c 77 69 6e 2d 78 36 34 5c 6e 61 74 69 76 65 5c 41 50 45 58 5f 54 4d 48 5f 4c 4f 41 44 45 52 2e 70 64 62 } //5 infinitycheats\GameHelpersLoader__APEX_TMH\GameHelpersLoader__APEX_TMH\bin\Release\net8.0-windows\win-x64\native\APEX_TMH_LOADER.pdb
		$a_01_1 = {69 6e 66 69 6e 69 74 79 63 68 65 61 74 73 5c 47 61 6d 65 48 65 6c 70 65 72 73 4c 6f 61 64 65 72 5f 5f 41 50 45 58 5f 54 4d 48 5c 47 61 6d 65 48 65 6c 70 65 72 73 4c 6f 61 64 65 72 5f 5f 41 50 45 58 5f 54 4d 48 5c 62 69 6e 5c 52 65 6c 65 61 73 65 5c 6e 65 74 38 2e 30 2d 77 69 6e 64 6f 77 73 5c 77 69 6e 2d 78 36 34 5c 6e 61 74 69 76 65 5c 47 61 6d 65 48 65 6c 70 65 72 73 4c 6f 61 64 65 72 5f 5f 41 50 45 58 5f 54 4d 48 2e 70 64 62 } //5 infinitycheats\GameHelpersLoader__APEX_TMH\GameHelpersLoader__APEX_TMH\bin\Release\net8.0-windows\win-x64\native\GameHelpersLoader__APEX_TMH.pdb
		$a_01_2 = {34 bb 32 71 70 da 5c 22 70 da 5c 22 70 da 5c 22 } //1
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1) >=6
 
}