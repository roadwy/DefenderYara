
rule Backdoor_Win64_SDBbot_A{
	meta:
		description = "Backdoor:Win64/SDBbot.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_01_0 = {57 41 54 41 55 41 56 41 57 48 } //2 WATAUAVAWH
		$a_01_1 = {56 57 41 54 41 56 41 57 48 } //2 VWATAVAWH
		$a_03_2 = {83 e0 7f 42 0f b6 0c ?? 0f b6 44 15 ?? 32 c8 88 4c 15 ?? 48 ff c2 48 83 fa ?? 72 e1 } //2
		$a_01_3 = {41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f 50 6e } //1 ABCDEFGHIJKLMNOPn
		$a_01_4 = {31 34 2e 31 32 31 2e 32 32 32 2e 31 31 } //1 14.121.222.11
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_03_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=7
 
}