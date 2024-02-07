
rule Trojan_WinNT_Adwind_L{
	meta:
		description = "Trojan:WinNT/Adwind.L,SIGNATURE_TYPE_JAVAHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {61 73 64 71 77 65 71 77 65 71 77 65 71 77 65 71 65 77 71 65 77 71 77 65 71 77 65 71 77 65 65 77 71 71 65 77 71 77 65 77 65 66 77 65 66 65 77 66 77 65 66 77 65 66 77 65 66 77 65 66 65 77 66 73 64 66 73 64 66 } //01 00  asdqweqweqweqweqewqewqweqweqweewqqewqwewefwefewfwefwefwefwefewfsdfsdf
		$a_01_1 = {77 65 66 77 65 66 61 64 66 73 64 66 73 64 66 73 64 66 73 64 66 73 64 66 73 64 66 73 64 66 73 64 66 } //00 00  wefwefadfsdfsdfsdfsdfsdfsdfsdfsdf
	condition:
		any of ($a_*)
 
}