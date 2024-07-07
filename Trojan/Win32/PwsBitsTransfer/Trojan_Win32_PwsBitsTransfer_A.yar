
rule Trojan_Win32_PwsBitsTransfer_A{
	meta:
		description = "Trojan:Win32/PwsBitsTransfer.A,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 6e 6f 70 20 2d 63 } //powershell.exe -nop -c  1
		$a_80_1 = {73 74 61 72 74 2d 6a 6f 62 20 7b } //start-job {  1
		$a_80_2 = {49 6d 70 6f 72 74 2d 4d 6f 64 75 6c 65 20 42 69 74 73 54 72 61 6e 73 66 65 72 } //Import-Module BitsTransfer  1
		$a_80_3 = {53 74 61 72 74 2d 42 69 74 73 54 72 61 6e 73 66 65 72 20 2d 53 6f 75 72 63 65 20 } //Start-BitsTransfer -Source   1
		$a_80_4 = {49 45 58 20 24 } //IEX $  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}