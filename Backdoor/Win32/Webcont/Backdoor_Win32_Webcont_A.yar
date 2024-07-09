
rule Backdoor_Win32_Webcont_A{
	meta:
		description = "Backdoor:Win32/Webcont.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {83 7c b5 c4 00 75 ?? 46 83 fe 0f 7c f3 8a 07 3c 65 74 0c 3c 70 74 08 3c 45 74 04 3c 50 75 01 47 8a 07 } //1
		$a_03_1 = {80 3f 30 75 15 8a 47 01 3c 78 74 04 3c 58 75 0a c7 45 ?? 10 00 00 00 83 c7 02 83 8d ?? ff ff ff ff 8a 07 3c 30 7c 12 3c 39 7f 0e 0f be 07 83 e8 30 } //1
		$a_00_2 = {43 6f 64 65 42 6f 78 44 69 61 6c 65 72 } //1 CodeBoxDialer
		$a_00_3 = {57 45 42 43 4f 4e 54 } //1 WEBCONT
		$a_00_4 = {25 30 32 69 3a 25 30 32 69 3a 25 30 32 69 } //1 %02i:%02i:%02i
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}