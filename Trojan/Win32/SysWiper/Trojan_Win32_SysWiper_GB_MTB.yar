
rule Trojan_Win32_SysWiper_GB_MTB{
	meta:
		description = "Trojan:Win32/SysWiper.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {63 6d 64 2e 65 78 65 20 2f 65 3a 4f 4e 20 2f 76 3a 4f 46 46 20 2f 64 20 2f 63 20 22 62 61 74 63 68 20 66 69 6c 65 20 61 72 67 75 6d 65 6e 74 73 20 61 72 65 20 69 6e 76 61 6c 69 64 } //1 cmd.exe /e:ON /v:OFF /d /c "batch file arguments are invalid
		$a_01_1 = {57 69 6e 64 6f 77 73 20 66 69 6c 65 20 6e 61 6d 65 73 20 6d 61 79 20 6e 6f 74 20 63 6f 6e 74 61 69 6e 20 60 22 60 } //1 Windows file names may not contain `"`
		$a_01_2 = {54 72 61 76 65 72 73 61 6c 77 69 70 65 72 2d 77 61 6c 6b 2d 64 69 73 70 61 74 63 68 65 72 } //1 Traversalwiper-walk-dispatcher
		$a_01_3 = {77 69 70 65 72 2e 70 64 62 } //1 wiper.pdb
		$a_01_4 = {57 69 70 65 72 45 72 72 6f 72 } //1 WiperError
		$a_01_5 = {64 65 73 63 72 69 70 74 69 6f 6e 28 29 20 69 73 20 64 65 70 72 65 63 61 74 65 64 3b 20 75 73 65 20 44 69 73 70 6c 61 79 } //1 description() is deprecated; use Display
		$a_01_6 = {63 72 6f 73 73 74 65 72 6d 3a 3a 63 75 72 73 6f 72 3a 3a 48 69 64 65 } //1 crossterm::cursor::Hide
		$a_01_7 = {2f 45 6e 74 65 72 2f 42 61 63 6b 73 70 61 63 65 20 2d 20 6e 61 76 69 67 61 74 65 73 72 63 } //1 /Enter/Backspace - navigatesrc
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}