
rule Trojan_Win32_Matcash_gen_E{
	meta:
		description = "Trojan:Win32/Matcash.gen!E,SIGNATURE_TYPE_PEHSTR,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {48 41 52 44 57 41 52 45 5c 44 45 53 43 52 49 50 54 49 4f 4e 5c 53 79 73 74 65 6d 5c 43 65 6e 74 72 61 6c 50 72 6f 63 65 73 73 6f 72 5c 30 } //2 HARDWARE\DESCRIPTION\System\CentralProcessor\0
		$a_01_1 = {63 70 76 2e 6c 62 61 6e 6e 2e 63 6f 6d } //1 cpv.lbann.com
		$a_01_2 = {43 50 56 36 2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 } //1 偃㙖䐮䱌䐀汬慃啮汮慯乤睯
		$a_01_3 = {2d 00 34 00 38 00 37 00 45 00 2d 00 42 00 33 00 39 00 39 00 2d 00 33 00 46 00 31 00 39 00 31 00 41 00 43 00 30 00 46 00 45 00 32 00 33 00 } //1 -487E-B399-3F191AC0FE23
		$a_01_4 = {75 70 6c 2e 6c 62 00 00 63 70 76 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}