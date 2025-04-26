
rule Trojan_Win32_Patched_T{
	meta:
		description = "Trojan:Win32/Patched.T,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {54 65 6d 70 c7 45 ?? 6f 72 61 72 } //1
		$a_01_1 = {eb 02 aa aa e9 80 03 00 00 8b 4c 24 04 56 8b 74 24 0c 8a 01 } //1
		$a_01_2 = {ff 55 ec 5f 5e 5b c9 c3 83 7c 24 08 01 75 07 60 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}