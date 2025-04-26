
rule Trojan_Win32_Dridex_SCD_MTB{
	meta:
		description = "Trojan:Win32/Dridex.SCD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 "
		
	strings :
		$a_80_0 = {65 6c 66 20 45 58 } //elf EX  3
		$a_80_1 = {45 53 20 41 50 50 20 45 5f } //ES APP E_  3
		$a_80_2 = {46 69 6e 64 45 78 65 63 75 74 61 62 6c 65 57 } //FindExecutableW  3
		$a_80_3 = {46 69 6e 64 4e 65 78 74 55 72 6c 43 61 63 68 65 47 72 6f 75 70 } //FindNextUrlCacheGroup  3
		$a_80_4 = {53 68 6f 77 4f 77 6e 65 64 50 6f 70 75 70 73 } //ShowOwnedPopups  3
		$a_80_5 = {53 74 61 72 74 53 65 72 76 69 63 65 43 74 72 6c 44 69 73 70 61 74 63 68 65 72 41 } //StartServiceCtrlDispatcherA  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3) >=18
 
}