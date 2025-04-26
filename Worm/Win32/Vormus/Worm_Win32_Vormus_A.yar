
rule Worm_Win32_Vormus_A{
	meta:
		description = "Worm:Win32/Vormus.A,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {54 00 4f 00 59 00 41 00 4e 00 4f 00 5c 00 6f 00 74 00 72 00 6f 00 73 00 20 00 76 00 69 00 72 00 75 00 73 00 69 00 6c 00 6c 00 6f 00 73 00 5c 00 73 00 68 00 65 00 6c 00 6c 00 33 00 32 00 5c 00 64 00 65 00 76 00 69 00 6c 00 20 00 73 00 68 00 65 00 6c 00 6c 00 33 00 32 00 2e 00 76 00 62 00 70 00 } //1 TOYANO\otros virusillos\shell32\devil shell32.vbp
		$a_01_1 = {54 45 20 41 20 4d 41 52 43 41 44 4f 20 4c 41 20 48 4f 52 41 20 43 48 41 4f 21 21 21 } //1 TE A MARCADO LA HORA CHAO!!!
		$a_01_2 = {64 65 74 65 63 74 61 72 20 75 73 62 73 } //1 detectar usbs
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}