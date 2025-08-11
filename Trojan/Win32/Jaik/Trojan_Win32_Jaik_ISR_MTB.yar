
rule Trojan_Win32_Jaik_ISR_MTB{
	meta:
		description = "Trojan:Win32/Jaik.ISR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {43 6e 64 6f 6d 36 2e 73 79 73 } //1 Cndom6.sys
		$a_81_1 = {58 69 61 6f 48 2e 73 79 73 } //1 XiaoH.sys
		$a_81_2 = {41 64 64 2d 4d 70 50 72 65 66 65 72 65 6e 63 65 20 2d 45 78 63 6c 75 73 69 6f 6e 50 61 74 68 20 27 43 3a 5c 5c 55 73 65 72 73 5c 5c 50 75 62 6c 69 63 5c 5c 44 6f 63 75 6d 65 6e 74 73 } //1 Add-MpPreference -ExclusionPath 'C:\\Users\\Public\\Documents
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}