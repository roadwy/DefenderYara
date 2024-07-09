
rule Backdoor_Win32_Afcore_gen_C{
	meta:
		description = "Backdoor:Win32/Afcore.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {74 16 6a 01 57 ff 56 70 33 c9 3b c1 74 06 51 53 51 51 ff d0 57 ff 56 18 } //2
		$a_03_1 = {68 00 30 10 00 ff 75 ?? 6a 00 ff 15 (90 09 14 00 0f|90 09 10 00 75) } //1
		$a_03_2 = {8a 0c 01 32 90 17 04 01 01 04 04 0a 0e 4a ?? 4e ?? [0-03] 88 0c 10 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}