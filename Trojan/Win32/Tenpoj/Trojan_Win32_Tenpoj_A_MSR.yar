
rule Trojan_Win32_Tenpoj_A_MSR{
	meta:
		description = "Trojan:Win32/Tenpoj.A!MSR,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {77 77 77 2e 31 32 33 34 35 36 61 62 63 67 73 64 77 65 72 65 35 36 34 36 33 34 35 35 33 34 35 34 33 35 34 33 35 36 35 37 32 32 32 32 32 32 2e 63 6f 6d } //01 00  www.123456abcgsdwere56463455345435435657222222.com
		$a_01_1 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 25 73 20 73 74 61 72 74 77 6f 72 6b } //01 00  rundll32.exe %s startwork
		$a_01_2 = {44 6f 63 75 6d 65 6e 74 73 5c 56 69 73 75 61 6c 20 53 74 75 64 69 6f 20 32 30 30 38 5c 50 72 6f 6a 65 63 74 73 5c 76 70 6e 65 74 5f 64 6c 6c 5c 52 65 6c 65 61 73 65 5c 76 70 6e 65 74 5f 64 6c 6c 2e 70 64 62 } //00 00  Documents\Visual Studio 2008\Projects\vpnet_dll\Release\vpnet_dll.pdb
	condition:
		any of ($a_*)
 
}