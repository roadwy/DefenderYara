
rule Trojan_Win32_BHO_KI{
	meta:
		description = "Trojan:Win32/BHO.KI,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 74 65 73 74 65 2e 67 74 } //1 C:\teste.gt
		$a_01_1 = {2a 68 65 69 6d 61 38 2a 2e 74 78 74 } //1 *heima8*.txt
		$a_01_2 = {62 69 67 65 74 63 6e 61 66 6e 2e 64 6c } //1 bigetcnafn.dl
		$a_01_3 = {73 2d 63 2e 2d 68 65 2d 6f 72 75 2e 63 2d 6f 6d } //1 s-c.-he-oru.c-om
		$a_01_4 = {73 2d 64 2e 2d 68 65 2d 6f 2d 72 75 2e 63 2d 6f 2d 6d } //1 s-d.-he-o-ru.c-o-m
		$a_01_5 = {38 32 44 41 46 30 36 42 2d 33 45 30 44 2d 32 46 31 44 2d 41 46 41 38 2d 39 35 39 44 44 44 33 45 38 42 45 33 } //1 82DAF06B-3E0D-2F1D-AFA8-959DDD3E8BE3
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}