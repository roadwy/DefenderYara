
rule Trojan_Win32_Agent_FS{
	meta:
		description = "Trojan:Win32/Agent.FS,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 12 0f b6 44 02 ff 89 45 e8 c7 45 ec 22 00 00 00 0f b7 45 f0 c1 e8 08 89 45 e4 c7 45 ec 4f 03 00 00 } //1
		$a_01_1 = {29 d0 c1 e0 02 89 c1 58 8b 40 18 8d 04 90 7c 0a 50 8d 50 04 } //1
		$a_03_2 = {03 c2 89 45 dc db 45 dc d8 35 90 01 02 40 00 de c1 8b 45 f8 dd 18 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}