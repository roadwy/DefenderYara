
rule Backdoor_Win32_Poison_gen_D{
	meta:
		description = "Backdoor:Win32/Poison.gen!D,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {58 50 56 53 53 ff 15 } //1
		$a_01_1 = {65 78 70 6c 6f 72 65 72 2e 65 78 65 00 00 00 00 43 75 72 72 65 6e 74 55 73 65 72 00 43 3a 5c 66 69 6c 65 2e 65 78 65 00 52 65 73 75 6d 65 54 68 } //1
		$a_01_2 = {6f 63 65 73 73 41 00 00 6d 5f 53 74 75 62 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}