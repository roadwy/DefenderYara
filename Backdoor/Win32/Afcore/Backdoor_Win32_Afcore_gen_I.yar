
rule Backdoor_Win32_Afcore_gen_I{
	meta:
		description = "Backdoor:Win32/Afcore.gen!I,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_01_0 = {4e 00 65 00 74 00 44 00 44 00 45 00 20 00 41 00 67 00 65 00 6e 00 74 00 20 00 25 00 31 00 20 00 43 00 6f 00 6d 00 69 00 6e 00 67 00 20 00 41 00 6c 00 69 00 76 00 65 00 } //1 NetDDE Agent %1 Coming Alive
		$a_01_1 = {5b 00 20 00 5b 00 20 00 76 00 65 00 72 00 62 00 6f 00 73 00 65 00 20 00 3d 00 20 00 5d 00 20 00 44 00 49 00 53 00 41 00 42 00 4c 00 45 00 7c 00 45 00 4e 00 41 00 42 00 4c 00 45 00 20 00 5d 00 } //1 [ [ verbose = ] DISABLE|ENABLE ]
		$a_03_2 = {6a 40 68 00 30 10 00 ff 73 90 01 01 6a 00 ff 15 90 00 } //10
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*10) >=11
 
}