
rule Trojan_Win32_Vidar_GNR_MTB{
	meta:
		description = "Trojan:Win32/Vidar.GNR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 08 03 85 90 01 04 0f be 18 ff 75 0c e8 90 01 04 59 8b c8 8b 85 90 01 04 33 d2 f7 f1 8b 45 0c 0f be 04 10 33 d8 8b 85 90 01 04 03 85 90 01 04 88 18 8d 85 90 01 04 50 90 00 } //10
		$a_01_1 = {4b 34 50 43 48 4f 58 45 32 4a 4a 42 41 4a } //1 K4PCHOXE2JJBAJ
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}