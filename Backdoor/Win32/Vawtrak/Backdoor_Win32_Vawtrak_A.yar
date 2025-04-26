
rule Backdoor_Win32_Vawtrak_A{
	meta:
		description = "Backdoor:Win32/Vawtrak.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {33 d2 6a 1a 59 f7 f1 83 c2 61 66 89 14 7b 47 3b fe 72 } //1
		$a_01_1 = {33 d2 6a 1a 59 f7 f1 80 c2 61 88 14 1f 47 3b fe 72 } //1
		$a_01_2 = {80 38 3a 75 03 50 eb 18 8b 45 f8 ff b0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule Backdoor_Win32_Vawtrak_A_2{
	meta:
		description = "Backdoor:Win32/Vawtrak.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {2b c8 8a 10 ff 4d 08 88 14 01 40 83 7d 08 00 } //2
		$a_01_1 = {8b 01 69 c0 fd 43 03 00 05 c3 9e 26 00 89 01 } //2
		$a_01_2 = {50 49 44 3a 20 25 75 20 5b 25 30 2e 32 75 3a 25 30 2e 32 75 3a 25 30 2e 32 75 5d } //1 PID: %u [%0.2u:%0.2u:%0.2u]
		$a_01_3 = {5b 53 6f 63 6b 73 5d 20 46 61 69 6c 74 20 63 6f 6e 6e 65 63 74 20 42 43 20 5b 25 73 3a 25 75 5d } //1 [Socks] Failt connect BC [%s:%u]
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}