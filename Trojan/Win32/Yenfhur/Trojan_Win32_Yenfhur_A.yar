
rule Trojan_Win32_Yenfhur_A{
	meta:
		description = "Trojan:Win32/Yenfhur.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {85 c0 75 79 68 ?? ?? ?? ?? 8d 4d b4 e8 ?? ?? ?? ?? c6 45 fc 03 8d 45 c0 50 8d 4d e4 e8 } //1
		$a_01_1 = {76 75 6d 65 72 2e 64 6c 6c 00 44 6c 6c } //1
		$a_01_2 = {72 65 73 73 69 67 6e 61 6d 65 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}