
rule TrojanSpy_Win32_Banker_LN{
	meta:
		description = "TrojanSpy:Win32/Banker.LN,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_02_0 = {2f 77 6f 72 6d [0-01] 2e 70 68 70 } //1
		$a_02_1 = {2f 77 61 62 [0-01] 2e 70 68 70 } //1
		$a_00_2 = {2a 2e 6d 62 78 00 } //1 ⸪扭x
		$a_00_3 = {2a 2e 65 6d 6c 00 } //1 ⸪浥l
		$a_00_4 = {6d 73 6f 65 40 6d 69 63 72 6f 73 6f 66 74 2e 63 6f 6d } //1 msoe@microsoft.com
		$a_00_5 = {53 6f 66 74 77 61 72 65 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 } //1 Software\Borland\Delphi
		$a_00_6 = {74 79 70 65 3d 22 6d 75 6c 74 69 70 61 72 74 2f 61 6c 74 65 72 6e 61 74 69 76 65 22 3b } //1 type="multipart/alternative";
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=7
 
}