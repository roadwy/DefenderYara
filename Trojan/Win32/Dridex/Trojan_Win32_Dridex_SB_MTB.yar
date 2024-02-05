
rule Trojan_Win32_Dridex_SB_MTB{
	meta:
		description = "Trojan:Win32/Dridex.SB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 08 00 00 03 00 "
		
	strings :
		$a_80_0 = {5d 53 5f 42 49 53 5f 26 } //]S_BIS_&  03 00 
		$a_80_1 = {52 61 73 47 65 74 41 75 74 6f 64 69 61 6c 41 64 64 72 65 73 73 57 } //RasGetAutodialAddressW  03 00 
		$a_80_2 = {46 69 6e 64 45 78 65 63 75 74 61 62 6c 65 57 } //FindExecutableW  03 00 
		$a_80_3 = {46 69 6e 64 4e 65 78 74 55 72 6c 43 61 63 68 65 47 72 6f 75 70 } //FindNextUrlCacheGroup  03 00 
		$a_80_4 = {53 68 6f 77 4f 77 6e 65 64 50 6f 70 75 70 73 } //ShowOwnedPopups  03 00 
		$a_80_5 = {53 74 61 72 74 53 65 72 76 69 63 65 43 74 72 6c 44 69 73 70 61 74 63 68 65 72 41 } //StartServiceCtrlDispatcherA  03 00 
		$a_80_6 = {52 65 61 64 46 69 6c 65 45 78 } //ReadFileEx  03 00 
		$a_80_7 = {54 65 72 6d 69 6e 61 74 65 4a 6f 62 4f 62 6a 65 63 74 } //TerminateJobObject  00 00 
	condition:
		any of ($a_*)
 
}