
rule Backdoor_Win32_Atadommoc_C{
	meta:
		description = "Backdoor:Win32/Atadommoc.C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {fe 45 17 8d 04 37 c0 20 04 8a 10 8a cb 80 e9 30 80 f9 09 77 06 0a ca 88 08 eb 11 8a cb 80 e9 61 80 f9 05 77 2f 80 eb 57 } //1
		$a_01_1 = {ff 4d fc c6 00 e9 89 48 01 75 } //1
		$a_01_2 = {63 6f 6d 6d 6f 6e 2e 64 61 74 61 00 } //1 潣浭湯搮瑡a
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}