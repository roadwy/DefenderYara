
rule Worm_Win32_Sixem_A{
	meta:
		description = "Worm:Win32/Sixem.A,SIGNATURE_TYPE_PEHSTR_EXT,24 00 24 00 06 00 00 "
		
	strings :
		$a_00_0 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 55 72 6c } //10 Software\Microsoft\Windows\CurrentVersion\Url
		$a_00_1 = {ff ff ff ff 06 00 00 00 69 6e 73 74 61 6c } //10
		$a_02_2 = {64 ff 30 64 89 20 6a 00 8b 45 fc e8 90 01 04 50 8d 45 fc e8 90 01 04 50 53 e8 90 01 04 33 c0 5a 59 59 64 89 10 68 90 01 04 8d 45 fc e8 90 01 04 c3 e9 90 01 04 eb f0 5b 59 5d 90 00 } //10
		$a_00_3 = {6d 61 69 6c 20 66 72 6f 6d } //5 mail from
		$a_00_4 = {2e 6a 70 67 } //1 .jpg
		$a_00_5 = {53 6f 63 63 65 72 } //1 Soccer
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_02_2  & 1)*10+(#a_00_3  & 1)*5+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=36
 
}