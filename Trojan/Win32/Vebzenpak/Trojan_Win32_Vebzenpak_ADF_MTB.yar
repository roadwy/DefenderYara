
rule Trojan_Win32_Vebzenpak_ADF_MTB{
	meta:
		description = "Trojan:Win32/Vebzenpak.ADF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0c 00 05 00 00 0a 00 "
		
	strings :
		$a_02_0 = {de 6f 84 00 c7 85 f8 90 01 03 a0 87 7b 3c c7 85 fc 90 01 03 06 5b 00 00 c7 85 48 90 01 03 54 b9 40 00 c7 85 40 90 01 03 08 00 00 00 8d 95 40 90 01 03 8d 8d 60 90 01 03 e8 d6 40 90 01 02 68 bc 13 00 00 8d 85 0c 90 01 03 50 8d 85 50 90 01 03 50 dd 05 40 12 40 00 51 51 dd 1c 24 8d 85 10 90 01 03 50 68 95 f5 3a 00 8d 85 f8 90 01 03 50 90 00 } //05 00 
		$a_80_1 = {54 49 50 4f 46 44 41 59 2e 54 58 54 } //TIPOFDAY.TXT  04 00 
		$a_80_2 = {52 4f 42 55 53 54 45 52 } //ROBUSTER  04 00 
		$a_80_3 = {53 54 41 52 54 50 55 4e 4b 54 45 54 } //STARTPUNKTET  04 00 
		$a_80_4 = {54 41 4c 4b 57 4f 52 54 48 59 } //TALKWORTHY  00 00 
	condition:
		any of ($a_*)
 
}