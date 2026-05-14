
rule HackTool_Win32_Keygen_RE_AMTB{
	meta:
		description = "HackTool:Win32/Keygen.RE!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {54 68 69 73 20 70 72 6f 67 72 61 6d 20 68 61 73 20 62 65 65 6e 20 63 72 61 63 6b 65 64 20 62 79 20 43 52 55 44 45 2e } //This program has been cracked by CRUDE.  1
		$a_80_1 = {46 69 6c 65 20 73 75 63 63 65 73 73 66 75 6c 6c 79 20 70 61 74 63 68 65 64 21 } //File successfully patched!  1
		$a_80_2 = {46 69 6c 65 20 73 65 65 6b 69 6e 67 20 66 61 69 6c 65 64 21 } //File seeking failed!  1
		$a_80_3 = {74 45 61 4d 20 63 52 75 44 65 } //tEaM cRuDe  1
		$a_80_4 = {6d 61 72 74 69 6e 20 67 61 6c 77 61 79 27 73 20 72 61 6d 62 6f } //martin galway's rambo  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}