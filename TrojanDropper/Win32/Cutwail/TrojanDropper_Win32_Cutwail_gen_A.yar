
rule TrojanDropper_Win32_Cutwail_gen_A{
	meta:
		description = "TrojanDropper:Win32/Cutwail.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {4f 8b 33 0f ce 8a ca d3 e6 c1 ee 1f 85 f6 74 06 8b cf d3 e6 03 c6 42 83 fa 20 75 05 83 c3 04 33 d2 85 ff 75 db 59 01 0d } //1
		$a_02_1 = {8b 00 03 c6 05 80 00 00 00 8b 18 03 de 8b 43 0c 03 45 08 50 ff 15 [0-06] 89 45 fc 8b 33 03 75 08 8b 7b 10 03 7d 08 8b 0e 03 4d 08 41 41 51 ff 75 fc ff 15 ?? ?? ?? ?? 89 07 83 c6 04 83 c7 04 83 3e 00 75 e2 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}