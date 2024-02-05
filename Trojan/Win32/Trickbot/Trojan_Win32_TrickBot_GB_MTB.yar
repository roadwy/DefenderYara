
rule Trojan_Win32_TrickBot_GB_MTB{
	meta:
		description = "Trojan:Win32/TrickBot.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {6a 00 6a 00 8a 90 02 03 03 e8 89 44 90 02 02 81 e5 ff 00 00 00 8a 5c 90 02 02 88 5c 90 02 02 88 44 90 02 02 ff 15 90 02 04 8a 4c 90 02 02 8b 84 90 02 05 02 d9 8a 90 02 02 81 90 01 01 ff 00 00 00 8a 90 02 03 32 90 01 01 88 90 02 02 8b 90 02 06 46 3b 90 02 09 81 c4 90 02 04 c3 90 0a 8d 00 47 33 90 02 03 ff 00 00 00 33 90 00 } //01 00 
		$a_80_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 4e 75 6d 61 } //VirtualAllocExNuma  00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_TrickBot_GB_MTB_2{
	meta:
		description = "Trojan:Win32/TrickBot.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 07 00 00 0a 00 "
		
	strings :
		$a_80_0 = {63 3a 5c 64 65 76 65 6c 6f 70 65 72 5c 77 65 62 69 6e 6a 65 63 74 5c 68 74 74 70 2d 6c 69 62 5c 70 61 72 73 65 72 2e 63 } //c:\developer\webinject\http-lib\parser.c  01 00 
		$a_80_1 = {64 61 74 61 5f 69 6e 6a 65 63 74 } //data_inject  01 00 
		$a_80_2 = {64 61 74 61 5f 62 65 66 6f 72 65 } //data_before  01 00 
		$a_80_3 = {64 61 74 61 5f 61 66 74 65 72 } //data_after  01 00 
		$a_80_4 = {64 61 74 61 5f 65 6e 64 } //data_end  01 00 
		$a_80_5 = {77 62 69 2d 78 38 36 2e 64 6c 6c } //wbi-x86.dll  01 00 
		$a_80_6 = {77 62 69 2d 78 36 34 2e 64 6c 6c } //wbi-x64.dll  00 00 
	condition:
		any of ($a_*)
 
}