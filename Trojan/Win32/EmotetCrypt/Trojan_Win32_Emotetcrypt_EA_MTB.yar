
rule Trojan_Win32_Emotetcrypt_EA_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.EA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_03_0 = {0f b6 14 37 8b 08 0f b6 04 33 03 c2 33 d2 f7 35 ?? ?? ?? ?? 8a 04 32 8b 55 ?? 32 04 11 8b 55 ?? ff 05 ?? ?? ?? ?? 88 04 11 a1 ?? ?? ?? ?? 3b 45 ?? 72 } //10
		$a_81_1 = {24 68 6a 25 6b 30 47 41 32 3f 32 2a 49 38 71 53 4d 45 33 35 25 79 4c 68 4b 30 35 46 41 4c 31 66 67 59 7a 7e 70 25 43 42 7e 37 63 52 6f 38 34 47 73 61 4e 48 52 6f 63 6a 68 37 6b 68 58 51 33 69 51 32 79 7c 3f 4b 23 59 50 71 74 } //1 $hj%k0GA2?2*I8qSME35%yLhK05FAL1fgYz~p%CB~7cRo84GsaNHRocjh7khXQ3iQ2y|?K#YPqt
		$a_81_2 = {61 6e 66 5a 40 75 49 4e 46 75 62 67 49 33 61 50 71 50 4d 3f 4e 72 25 7d 49 6b 53 39 31 53 33 71 52 32 4a 23 52 70 2a 44 6c 66 64 77 68 79 52 52 6c 34 43 37 23 70 6a 75 58 51 4e 4a 72 65 62 71 32 5a 70 6f 52 76 47 45 77 53 25 43 } //1 anfZ@uINFubgI3aPqPM?Nr%}IkS91S3qR2J#Rp*DlfdwhyRRl4C7#pjuXQNJrebq2ZpoRvGEwS%C
	condition:
		((#a_03_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=11
 
}