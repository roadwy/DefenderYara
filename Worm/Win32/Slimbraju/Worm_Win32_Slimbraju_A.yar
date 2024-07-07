
rule Worm_Win32_Slimbraju_A{
	meta:
		description = "Worm:Win32/Slimbraju.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {2f 00 7e 00 62 00 6c 00 34 00 63 00 6b 00 2f 00 } //1 /~bl4ck/
		$a_01_1 = {6c 6f 73 74 3d 45 78 70 6c 6f 72 61 72 } //1 lost=Explorar
		$a_01_2 = {73 61 6d 70 6c 65 00 00 4a 61 62 75 } //1
		$a_01_3 = {70 6c 61 79 6c 69 00 00 ff ff ff ff 06 00 00 00 73 74 2e 6d 33 75 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}