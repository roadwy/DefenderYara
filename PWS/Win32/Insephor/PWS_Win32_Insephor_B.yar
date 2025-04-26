
rule PWS_Win32_Insephor_B{
	meta:
		description = "PWS:Win32/Insephor.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {7e 2a bb 01 00 00 00 8d 45 f4 8d 53 05 33 c9 8a 4c 1f ff 83 e9 ?? 33 d1 e8 } //1
		$a_03_1 = {83 3a 01 0f 85 ?? ?? ?? ?? 83 c0 20 66 8b 18 66 c7 42 04 6b 00 66 c7 42 06 4e 00 66 83 fb 6b 0f 84 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}