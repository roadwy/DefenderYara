
rule Trojan_Win32_Masson_B{
	meta:
		description = "Trojan:Win32/Masson.B,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {43 73 72 73 73 20 62 79 20 4d 69 63 6f 73 6f 66 74 } //1 Csrss by Micosoft
		$a_01_1 = {4d 69 63 6f 73 6f 66 74 20 49 6e 63 } //1 Micosoft Inc
		$a_01_2 = {37 35 39 33 64 62 63 62 2d 65 65 30 35 2d 34 34 64 64 2d 61 32 65 35 2d 36 35 38 38 30 33 66 35 63 64 64 65 } //1 7593dbcb-ee05-44dd-a2e5-658803f5cdde
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}