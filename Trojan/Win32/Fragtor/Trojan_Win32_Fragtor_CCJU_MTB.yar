
rule Trojan_Win32_Fragtor_CCJU_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.CCJU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 4d 69 63 72 6f 73 6f 66 74 5c 50 72 6f 67 72 61 6d 5c 7a 69 6c 69 61 6f 2e 6a 70 67 } //2 C:\ProgramData\Microsoft\Program\ziliao.jpg
		$a_01_1 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 4d 69 63 72 6f 73 6f 66 74 5c 45 64 67 65 55 70 64 61 74 65 5c 4c 6f 67 5c 63 68 75 61 6e 67 6b 6f 75 2e 6c 6f 67 } //2 C:\ProgramData\Microsoft\EdgeUpdate\Log\chuangkou.log
		$a_01_2 = {5c 73 68 65 6c 6c 63 6f 64 65 5c } //1 \shellcode\
		$a_01_3 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}