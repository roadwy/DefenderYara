
rule PWS_Win32_Cupsop_B{
	meta:
		description = "PWS:Win32/Cupsop.B,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0a 00 06 00 00 "
		
	strings :
		$a_03_0 = {7e 09 80 34 31 ?? 41 3b c8 7c f7 } //1
		$a_03_1 = {40 3b 45 fc 7d 11 8a 0c 18 80 f9 2a 74 f2 88 8f ?? ?? ?? ?? 47 eb e9 c6 87 ?? ?? ?? ?? 20 } //1
		$a_01_2 = {c0 e0 02 80 e2 3f 46 0a c2 34 eb 88 04 1e 46 ff 4d f8 75 84 } //1
		$a_00_3 = {3c 42 52 3e d4 aa b1 a6 3c 66 6f 6e 74 20 63 6f 6c 6f 72 3d 52 45 44 3e 00 } //4
		$a_00_4 = {3c 42 52 3e c8 cb ce ef 32 c3 fb b3 c6 3a 20 00 } //4
		$a_00_5 = {c8 cb ce ef 31 b5 c8 bc b6 3a 20 00 } //4
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*4+(#a_00_4  & 1)*4+(#a_00_5  & 1)*4) >=10
 
}