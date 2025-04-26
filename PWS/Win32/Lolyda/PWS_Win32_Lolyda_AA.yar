
rule PWS_Win32_Lolyda_AA{
	meta:
		description = "PWS:Win32/Lolyda.AA,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 57 56 8b 7d 08 8b 75 0c ac 0a c0 74 03 32 45 10 aa 80 3e 00 75 06 80 7e 01 00 74 02 eb ea 5e 5f c9 c2 0c 00 } //1
		$a_01_1 = {55 8b ec 57 56 51 8b 7d 08 8b 75 0c 8b 4d 10 0b c9 74 07 ac 32 45 14 aa e2 f9 59 5e 5f c9 c2 10 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}