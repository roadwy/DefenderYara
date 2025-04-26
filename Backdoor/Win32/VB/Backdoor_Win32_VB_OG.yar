
rule Backdoor_Win32_VB_OG{
	meta:
		description = "Backdoor:Win32/VB.OG,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 "
		
	strings :
		$a_01_0 = {52 74 6c 4d 6f 76 65 4d 65 6d 6f 72 79 } //1 RtlMoveMemory
		$a_01_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
		$a_01_2 = {53 00 71 00 55 00 65 00 45 00 7a 00 45 00 72 00 } //2 SqUeEzEr
		$a_01_3 = {54 00 75 00 76 00 63 00 51 00 62 00 75 00 69 00 } //2 TuvcQbui
		$a_01_4 = {54 00 70 00 67 00 75 00 78 00 62 00 73 00 66 00 5d 00 4e 00 6a 00 64 00 73 00 70 00 74 00 70 00 67 00 75 00 5d 00 42 00 64 00 75 00 6a 00 77 00 66 00 21 00 54 00 66 00 75 00 76 00 71 00 5d 00 4a 00 6f 00 74 00 75 00 62 00 6d 00 6d 00 66 00 65 00 21 00 44 00 70 00 6e 00 71 00 70 00 6f 00 66 00 6f 00 75 00 74 00 5d 00 } //3 Tpguxbsf]Njdsptpgu]Bdujwf!Tfuvq]Jotubmmfe!Dpnqpofout]
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*3) >=9
 
}