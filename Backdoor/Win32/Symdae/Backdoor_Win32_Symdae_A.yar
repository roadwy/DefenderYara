
rule Backdoor_Win32_Symdae_A{
	meta:
		description = "Backdoor:Win32/Symdae.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 7c 24 10 8b d7 2b cf 8a 04 11 8a 1a 32 d8 88 1a 42 4e 75 f3 8b c7 } //1
		$a_03_1 = {68 a0 bb 0d 00 ff 15 ?? ?? ?? ?? b8 6e 3a 00 10 c3 33 db 89 5d fc } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}