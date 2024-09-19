
rule Trojan_Win32_Stealc_AMAJ_MTB{
	meta:
		description = "Trojan:Win32/Stealc.AMAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 55 ff 83 c2 01 81 e2 ff 00 00 00 88 55 ff 0f b6 45 ff 8b 4d f8 0f b6 14 01 0f b6 45 fe 03 d0 81 e2 ff 00 00 00 88 55 fe 0f b6 4d ff 8b 55 f8 8a 04 0a 88 45 fd 0f b6 4d fe 0f b6 55 ff 8b 45 f8 8b 75 f8 8a 0c 0e 88 0c 10 0f b6 55 fe 8b 45 f8 8a 4d fd 88 0c 10 0f b6 55 ff 8b 45 f8 0f b6 0c 10 0f b6 55 fe 8b 45 f8 0f b6 14 10 03 ca 81 e1 ff 00 00 00 8b 45 f8 0f b6 0c 08 8b 55 08 03 55 f4 0f b6 02 33 c1 8b 4d 08 03 4d f4 88 01 } //2
		$a_01_1 = {6a 04 68 00 30 00 00 8b 4d ec 51 6a 00 ff 15 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}