
rule Virus_Win32_Mesoum{
	meta:
		description = "Virus:Win32/Mesoum,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 75 3c 8b 74 2e 78 03 f5 56 8b 76 20 03 f5 33 c9 49 41 ad 03 c5 33 db 0f be 10 3a d6 74 08 c1 cb 0d 03 da 40 eb f1 3b df 75 e7 5e 8b 5e 24 03 dd 66 8b 0c 4b 8b 5e 1c 03 dd 8b 04 8b 03 c5 } //1
		$a_03_1 = {31 14 24 54 ff d0 59 59 61 e8 00 00 00 00 59 81 ?? ?? ?? ff ff 8b 11 ff d2 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}