
rule Trojan_Win32_VBInject_VA_MTB{
	meta:
		description = "Trojan:Win32/VBInject.VA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 08 00 00 03 00 "
		
	strings :
		$a_80_0 = {44 65 6d 61 72 6b 61 74 69 6f 6e 73 6c 69 6e 6a 65 6e 73 37 } //Demarkationslinjens7  03 00 
		$a_80_1 = {6e 65 72 76 65 6d 65 64 69 63 69 6e 73 } //nervemedicins  03 00 
		$a_80_2 = {6b 6e 6f 70 73 6b 79 64 65 } //knopskyde  03 00 
		$a_80_3 = {73 74 6e 69 6e 67 73 73 74 72 75 6b 74 75 72 65 72 } //stningsstrukturer  03 00 
		$a_80_4 = {45 6d 70 74 79 43 6c 69 70 62 6f 61 72 64 } //EmptyClipboard  03 00 
		$a_80_5 = {48 69 64 65 43 61 72 65 74 } //HideCaret  03 00 
		$a_80_6 = {47 65 74 46 69 6c 65 49 6e 66 6f 72 6d 61 74 69 6f 6e 42 79 48 61 6e 64 6c 65 } //GetFileInformationByHandle  03 00 
		$a_80_7 = {57 4e 65 74 47 65 74 55 73 65 72 41 } //WNetGetUserA  00 00 
	condition:
		any of ($a_*)
 
}