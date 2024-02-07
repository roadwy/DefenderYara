
rule Trojan_Win32_Rigtoy{
	meta:
		description = "Trojan:Win32/Rigtoy,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 07 00 00 03 00 "
		
	strings :
		$a_01_0 = {25 73 3f 67 69 64 3d 25 64 26 25 73 } //03 00  %s?gid=%d&%s
		$a_01_1 = {41 64 6f 62 65 41 69 64 2e 64 6c 6c } //01 00  AdobeAid.dll
		$a_01_2 = {62 61 69 64 75 2e 63 6f 6d } //02 00  baidu.com
		$a_01_3 = {47 50 6c 61 79 65 72 2e 64 6c 6c } //03 00  GPlayer.dll
		$a_01_4 = {53 79 73 5f 52 75 6e 5f 33 } //01 00  Sys_Run_3
		$a_01_5 = {79 61 68 6f 6f 2e 63 6f 6d 2e 63 6e } //01 00  yahoo.com.cn
		$a_01_6 = {7a 68 6f 6e 67 73 6f 75 2e 63 6f 6d } //00 00  zhongsou.com
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Rigtoy_2{
	meta:
		description = "Trojan:Win32/Rigtoy,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {52 75 6e 00 00 00 00 20 00 00 00 5c 72 75 6e 64 6c 6c 33 32 2e 65 78 65 00 00 00 2e 63 75 72 00 00 00 00 5c 63 75 72 73 6f 72 00 2e 73 79 73 00 00 00 00 5c 64 72 69 76 65 72 73 00 00 00 00 2e 74 74 66 00 00 00 00 2e 65 78 65 00 00 00 00 2e 64 6c 6c 00 00 00 00 5c 4d 53 00 20 2d 73 00 20 2d 69 } //02 00 
		$a_01_1 = {53 79 73 5f 52 75 6e 5f 33 } //02 00  Sys_Run_3
		$a_01_2 = {53 47 4d 49 47 45 58 } //02 00  SGMIGEX
		$a_01_3 = {41 64 6f 62 65 41 69 64 2e 64 6c 6c } //02 00  AdobeAid.dll
		$a_01_4 = {4d 73 4e 65 74 45 78 2e 65 78 65 } //02 00  MsNetEx.exe
		$a_00_5 = {4d 00 6f 00 64 00 75 00 6c 00 65 00 5f 00 52 00 61 00 77 00 } //00 00  Module_Raw
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Rigtoy_3{
	meta:
		description = "Trojan:Win32/Rigtoy,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {5c 72 75 6e 64 6c 6c 33 32 2e 65 78 65 00 00 00 2e 63 75 72 00 00 00 00 5c 63 75 72 73 6f 72 00 2e 73 79 73 00 00 00 00 5c 64 72 69 76 65 72 73 00 00 00 00 2e 74 74 66 00 00 00 00 2e 65 78 65 00 00 00 00 2e 64 6c 6c 00 00 00 00 5c 4d 53 } //02 00 
		$a_01_1 = {4f 4c 45 4e 00 00 00 00 45 54 2e 64 6c 6c 00 00 41 64 6f 62 65 00 00 00 41 69 64 2e 64 6c 6c 00 4d 73 4e 65 74 00 00 00 45 78 2e 65 78 65 00 00 49 4d 53 47 4d 49 47 } //02 00 
		$a_01_2 = {53 79 73 5f 00 00 00 00 52 75 6e 5f 32 00 00 00 52 75 6e 5f 31 00 00 00 6d 61 70 00 52 75 6e 5f 33 } //02 00 
		$a_01_3 = {53 47 4d 49 47 45 58 } //00 00  SGMIGEX
	condition:
		any of ($a_*)
 
}