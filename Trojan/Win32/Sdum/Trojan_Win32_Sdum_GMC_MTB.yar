
rule Trojan_Win32_Sdum_GMC_MTB{
	meta:
		description = "Trojan:Win32/Sdum.GMC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 07 8b d1 83 e2 03 8a 54 3a 0c 03 c1 30 10 41 3b 4f 04 72 eb } //10
		$a_01_1 = {0f b6 4d dd 0f b6 47 0d 0f b6 55 dc 33 c1 0f b6 4f 0c c1 e0 08 33 ca } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}