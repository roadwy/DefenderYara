
rule Worm_Win32_Cambot_C{
	meta:
		description = "Worm:Win32/Cambot.C,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {5c 00 70 00 73 00 70 00 77 00 2e 00 62 00 73 00 73 00 } //1 \pspw.bss
		$a_01_1 = {53 00 65 00 6c 00 65 00 63 00 74 00 20 00 2a 00 20 00 66 00 72 00 6f 00 6d 00 20 00 41 00 6e 00 74 00 69 00 56 00 69 00 72 00 75 00 73 00 50 00 72 00 6f 00 64 00 75 00 63 00 74 00 } //1 Select * from AntiVirusProduct
		$a_01_2 = {78 00 61 00 6d 00 70 00 70 00 5c 00 68 00 74 00 64 00 6f 00 63 00 73 00 } //1 xampp\htdocs
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}