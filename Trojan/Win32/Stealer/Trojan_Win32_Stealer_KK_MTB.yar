
rule Trojan_Win32_Stealer_KK_MTB{
	meta:
		description = "Trojan:Win32/Stealer.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 03 00 00 "
		
	strings :
		$a_01_0 = {8a 0c 33 8a c3 02 c5 33 d2 34 55 02 c8 c0 e0 03 32 c8 8b c3 6a 07 5f f7 f7 02 ca 88 0c 33 43 3b 5d 0c } //20
		$a_01_1 = {0f b6 c2 6b d0 0d 80 c2 11 30 14 31 41 3b 4d 0c } //10
		$a_01_2 = {03 c6 69 c0 fb 00 00 00 83 c0 61 33 c1 69 c0 dd 02 00 00 0f b7 c0 33 c3 99 } //5
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10+(#a_01_2  & 1)*5) >=35
 
}