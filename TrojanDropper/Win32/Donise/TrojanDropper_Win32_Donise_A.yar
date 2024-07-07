
rule TrojanDropper_Win32_Donise_A{
	meta:
		description = "TrojanDropper:Win32/Donise.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {e8 0f 00 00 00 26 80 ac c8 33 db 64 8f 03 59 90 } //2
		$a_01_1 = {75 07 c7 45 e4 12 ef cd ab 8b 75 08 } //2
		$a_01_2 = {72 73 79 6e 63 69 6e 69 2e 65 78 65 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=3
 
}