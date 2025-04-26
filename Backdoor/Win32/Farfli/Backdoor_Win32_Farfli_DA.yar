
rule Backdoor_Win32_Farfli_DA{
	meta:
		description = "Backdoor:Win32/Farfli.DA,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 8a 1c 10 89 4d e8 8a 0c 31 32 d9 b9 05 00 00 00 88 1c 10 99 f7 f9 85 d2 } //1
		$a_01_1 = {66 81 38 4d 5a 74 0a 5f 5e 5d 33 c0 5b 83 c4 64 c3 8b 70 3c 03 f0 89 74 24 20 81 3e 50 45 00 00 74 0a } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}