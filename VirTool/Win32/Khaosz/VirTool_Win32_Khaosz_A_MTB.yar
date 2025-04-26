
rule VirTool_Win32_Khaosz_A_MTB{
	meta:
		description = "VirTool:Win32/Khaosz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_81_0 = {74 69 61 67 6f 72 6c 61 6d 70 65 72 74 2f 43 48 41 4f 53 } //2 tiagorlampert/CHAOS
		$a_81_1 = {67 69 74 68 75 62 2e 63 6f 6d 2f 6d 61 74 69 73 68 73 69 61 6f } //1 github.com/matishsiao
		$a_81_2 = {6b 62 69 6e 61 6e 69 2f 73 63 72 65 65 6e 73 68 6f 74 } //1 kbinani/screenshot
		$a_81_3 = {63 6c 69 65 6e 74 2f 61 70 70 2f 75 73 65 63 61 73 65 2f 75 70 6c 6f 61 64 2f 75 70 6c 6f 61 64 5f 75 73 65 63 61 73 65 2e 67 6f } //1 client/app/usecase/upload/upload_usecase.go
		$a_81_4 = {67 69 74 68 75 62 2e 63 6f 6d 2f 6c 78 6e 2f 77 69 6e } //1 github.com/lxn/win
		$a_03_5 = {76 69 63 74 69 6d [0-20] 77 69 6e 64 6f 77 [0-20] 77 72 69 74 65 72 } //1
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_03_5  & 1)*1) >=4
 
}