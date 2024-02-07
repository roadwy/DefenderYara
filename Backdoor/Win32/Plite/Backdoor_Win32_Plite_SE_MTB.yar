
rule Backdoor_Win32_Plite_SE_MTB{
	meta:
		description = "Backdoor:Win32/Plite.SE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {8b 06 8b c8 c1 f9 05 8b 0c 8d a0 57 42 00 83 e0 1f c1 e0 06 8d 44 01 24 8a 08 32 4d fe 80 e1 7f 30 08 8b 06 8b c8 c1 f9 05 } //01 00 
		$a_01_1 = {69 66 20 65 78 69 73 74 20 22 25 73 22 20 67 6f 74 6f 20 52 65 70 65 61 74 0d 0a 72 6d 64 69 72 20 22 25 73 22 0d 0a 64 65 6c 20 22 25 73 } //01 00  晩攠楸瑳∠猥•潧潴删灥慥൴爊摭物∠猥ഢ搊汥∠猥
		$a_01_2 = {48 61 6e 41 67 65 6e 74 5f 70 65 2e 65 78 65 } //00 00  HanAgent_pe.exe
	condition:
		any of ($a_*)
 
}