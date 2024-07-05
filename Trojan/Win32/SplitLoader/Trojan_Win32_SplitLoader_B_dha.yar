
rule Trojan_Win32_SplitLoader_B_dha{
	meta:
		description = "Trojan:Win32/SplitLoader.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 01 00 00 64 00 "
		
	strings :
		$a_01_0 = {3a 5c 77 6f 72 6b 73 70 61 63 65 5c 43 42 47 5c 4c 6f 61 64 65 72 5c 53 70 6c 69 74 4c 6f 61 64 65 72 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 53 70 6c 69 74 4c 6f 61 64 65 72 2e 70 64 62 } //00 00  :\workspace\CBG\Loader\SplitLoader\x64\Release\SplitLoader.pdb
	condition:
		any of ($a_*)
 
}