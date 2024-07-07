
rule Trojan_Win32_Qbot_PAE_MTB{
	meta:
		description = "Trojan:Win32/Qbot.PAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 a8 03 45 ac 48 89 45 a4 8b 45 a8 8b 55 d8 01 02 8b 45 c4 03 45 a4 89 45 a0 8b 45 d8 8b 00 33 45 a0 89 45 a0 8b 45 a0 8b 55 d8 89 02 33 c0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qbot_PAE_MTB_2{
	meta:
		description = "Trojan:Win32/Qbot.PAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {80 45 f9 2a c6 45 fa 00 66 3b db 74 00 bb 41 77 26 07 83 c3 0b eb 53 80 45 f4 4c c6 45 f5 55 66 3b e4 74 19 83 ec 18 c6 45 f4 29 66 3b e4 74 e7 80 45 f7 46 c6 45 f8 02 66 3b d2 74 20 80 45 f5 } //2
		$a_01_1 = {44 46 39 41 64 6d 50 } //1 DF9AdmP
		$a_01_2 = {46 37 4d 49 6c 63 37 6b 4a 6e 6d } //1 F7MIlc7kJnm
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}