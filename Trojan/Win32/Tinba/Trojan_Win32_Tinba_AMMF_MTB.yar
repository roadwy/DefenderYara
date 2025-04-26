
rule Trojan_Win32_Tinba_AMMF_MTB{
	meta:
		description = "Trojan:Win32/Tinba.AMMF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {6d 4b 6f 53 51 6e 48 79 70 43 4d } //mKoSQnHypCM  1
		$a_80_1 = {4e 49 4a 4d 78 71 78 63 43 6f } //NIJMxqxcCo  1
		$a_80_2 = {4f 72 4b 71 4e 67 67 72 6c 44 6d 4a 74 } //OrKqNggrlDmJt  1
		$a_80_3 = {44 3a 5c 4d 61 7a 2d 6d 69 6c 6f 63 65 76 69 63 34 5c 46 6c 61 73 68 47 61 6d 65 73 2e 76 62 70 } //D:\Maz-milocevic4\FlashGames.vbp  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}