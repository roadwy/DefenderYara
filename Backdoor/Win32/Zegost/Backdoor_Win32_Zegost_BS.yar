
rule Backdoor_Win32_Zegost_BS{
	meta:
		description = "Backdoor:Win32/Zegost.BS,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {5b 45 6e 74 65 72 5d 00 5b 45 53 43 5d 00 } //1 䕛瑮牥]䕛䍓]
		$a_01_1 = {c6 45 d4 5c c6 45 d5 78 c6 45 d6 78 c6 45 d7 6f c6 45 d8 6f c6 45 d9 78 c6 45 da 78 c6 45 db 2e c6 45 dc 4c c6 45 dd 4f c6 45 de 47 } //1
		$a_03_2 = {ff 77 c6 85 90 01 02 ff ff 64 c6 85 90 01 02 ff ff 5c c6 85 90 01 02 ff ff 54 c6 85 90 01 02 ff ff 64 c6 85 90 01 02 ff ff 73 c6 85 90 01 02 ff ff 5c c6 85 90 01 02 ff ff 74 c6 85 90 01 02 ff ff 63 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}