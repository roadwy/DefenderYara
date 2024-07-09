
rule Trojan_Win32_Darhack_A{
	meta:
		description = "Trojan:Win32/Darhack.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {43 72 79 70 74 5c 44 61 72 45 79 65 } //1 Crypt\DarEye
		$a_00_1 = {43 72 61 63 6b 65 64 20 62 79 } //1 Cracked by
		$a_02_2 = {79 71 63 63 62 6e [0-08] 63 72 65 6d 65 } //1
		$a_00_3 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}