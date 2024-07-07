
rule Trojan_Win32_TrickBotCrypt_GU_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.GU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_02_0 = {8a 45 0f 8b 4d 08 83 c4 18 3b 75 90 01 01 73 15 90 01 01 8a d3 2a d1 80 e2 20 32 13 32 d0 88 13 03 df 3b 5d fc 72 90 00 } //10
		$a_81_1 = {50 44 53 56 53 4f 44 6e 61 73 62 79 76 64 67 70 6e 69 6b 6e 61 73 62 64 6e 67 68 69 } //1 PDSVSODnasbyvdgpniknasbdnghi
		$a_81_2 = {46 4c 4f 43 6d 61 74 68 6a 61 6e 75 61 72 79 31 37 31 32 32 63 6f 6d 70 6c 65 78 } //1 FLOCmathjanuary17122complex
		$a_81_3 = {53 69 65 6c 65 74 57 } //1 SieletW
	condition:
		((#a_02_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=12
 
}