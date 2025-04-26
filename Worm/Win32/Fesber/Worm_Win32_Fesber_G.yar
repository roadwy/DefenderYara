
rule Worm_Win32_Fesber_G{
	meta:
		description = "Worm:Win32/Fesber.G,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {46 53 42 2d 49 53 2d 4d 59 2d 48 45 57 52 4f } //1 FSB-IS-MY-HEWRO
		$a_01_1 = {43 3a 5c 66 73 62 2e 73 74 62 } //1 C:\fsb.stb
		$a_01_2 = {5c 6e 6f 74 70 61 64 2e 65 78 65 } //1 \notpad.exe
		$a_01_3 = {5c 66 73 62 2e 74 6d 70 } //1 \fsb.tmp
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}