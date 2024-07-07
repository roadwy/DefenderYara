
rule HackTool_Win32_Kirbikator{
	meta:
		description = "HackTool:Win32/Kirbikator,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 09 00 00 "
		
	strings :
		$a_80_0 = {6b 69 72 62 69 7c 63 63 61 63 68 65 7c 77 63 65 7c 6c 73 61 7c 6b 69 72 62 69 73 7c 63 63 61 63 68 65 73 7c 77 63 65 73 } //kirbi|ccache|wce|lsa|kirbis|ccaches|wces  1
		$a_80_1 = {6b 69 77 69 5f 63 63 61 63 68 65 5f 72 65 61 64 } //kiwi_ccache_read  1
		$a_80_2 = {6b 69 77 69 5f 77 63 65 5f 72 65 61 64 } //kiwi_wce_read  1
		$a_80_3 = {6b 69 77 69 5f 63 63 61 63 68 65 5f 73 69 7a 65 5f 68 65 61 64 65 72 5f 6b 72 62 63 72 65 64 } //kiwi_ccache_size_header_krbcred  1
		$a_80_4 = {6b 69 72 62 69 6b 61 74 6f 72 } //kirbikator  1
		$a_80_5 = {4c 73 61 43 61 6c 6c 41 75 74 68 65 6e 74 69 63 61 74 69 6f 6e 50 61 63 6b 61 67 65 } //LsaCallAuthenticationPackage  1
		$a_80_6 = {6b 72 62 63 72 65 64 69 6e 66 6f } //krbcredinfo  1
		$a_80_7 = {74 69 63 6b 65 74 2d 69 6e 66 6f } //ticket-info  1
		$a_80_8 = {67 65 6e 74 69 6c 6b 69 77 69 } //gentilkiwi  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1) >=6
 
}