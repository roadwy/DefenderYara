
rule Trojan_Win32_Agent_gen_ACE{
	meta:
		description = "Trojan:Win32/Agent.gen!ACE,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_01_0 = {57 53 63 72 69 70 74 } //10 WScript
		$a_01_1 = {52 64 75 21 65 60 75 64 3c 24 65 60 75 64 24 } //1 Rdu!e`ud<$e`ud$
		$a_03_2 = {73 64 66 21 60 65 65 21 49 4a 44 58 5e 4d 4e 42 40 4d 5e 4c 40 42 49 48 4f 44 5d 52 4e 47 55 56 40 53 44 5d 4c 48 42 53 4e 52 4e 47 55 5d 56 48 4f 45 4e 56 52 5d 42 54 53 53 44 4f 55 57 44 53 52 48 4e 4f 5d 53 54 4f 21 2e 57 21 52 57 42 49 4e 52 55 52 2f 44 59 44 21 2e 55 21 53 44 46 5e 52 5b 21 2e 45 21 42 3b 5d 56 48 4f 45 4e 56 52 5d 52 58 52 55 44 4c 32 33 5d [0-10] 44 59 44 21 2e 47 } //1
		$a_01_3 = {65 60 75 64 21 30 38 } //1 e`ud!08
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=13
 
}