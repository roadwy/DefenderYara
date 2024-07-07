
rule TrojanProxy_Win32_Tikayb_A{
	meta:
		description = "TrojanProxy:Win32/Tikayb.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {d1 ed 33 ea 2b cd 30 08 8a 10 4e 40 85 f6 75 e4 } //1
		$a_01_1 = {81 f9 00 fa 00 00 7d 06 3b c3 74 db eb 04 3b c3 74 16 } //1
		$a_01_2 = {c6 44 24 2c 05 c6 44 24 2d 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}