
rule TrojanSpy_BAT_Stealergen_ME_MTB{
	meta:
		description = "TrojanSpy:BAT/Stealergen.ME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 "
		
	strings :
		$a_01_0 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 63 00 64 00 6e 00 2e 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 2f 00 61 00 74 00 74 00 61 00 63 00 68 00 6d 00 65 00 6e 00 74 00 73 00 } //1 https://cdn.discordapp.com/attachments
		$a_00_1 = {11 04 11 05 11 04 11 05 91 20 a7 02 00 00 59 d2 9c 00 11 05 17 58 13 05 11 05 11 04 8e 69 fe 04 13 06 11 06 2d d9 } //1
		$a_01_2 = {4a 4b 41 57 4e 46 55 49 41 49 46 47 } //1 JKAWNFUIAIFG
		$a_01_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_4 = {57 65 62 52 65 73 70 6f 6e 73 65 } //1 WebResponse
		$a_01_5 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_01_6 = {54 6f 53 74 72 69 6e 67 } //1 ToString
		$a_01_7 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //1 MemoryStream
		$a_01_8 = {47 65 74 44 6f 6d 61 69 6e } //1 GetDomain
		$a_01_9 = {73 65 74 5f 50 61 73 73 77 6f 72 64 43 68 61 72 } //1 set_PasswordChar
		$a_01_10 = {47 65 74 52 65 73 70 6f 6e 73 65 } //1 GetResponse
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=11
 
}