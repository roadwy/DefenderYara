
rule Backdoor_Win32_Poison_BP{
	meta:
		description = "Backdoor:Win32/Poison.BP,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {74 6f 8d 44 24 10 6a 00 50 55 53 57 ff 15 } //1
		$a_01_1 = {7e 54 58 45 00 00 00 00 42 49 4e 00 } //1
		$a_01_2 = {88 48 fe 80 c1 02 c0 e1 04 88 0c 3e 8a 50 ff 80 ea 1e 32 d1 88 14 3e 46 3b f3 7c } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2) >=2
 
}