
rule Trojan_Win32_Shodi_YBG_MTB{
	meta:
		description = "Trojan:Win32/Shodi.YBG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {56 59 e8 90 ff ff ff 83 f8 01 0f 8e be 00 00 00 56 59 e8 96 ff ff ff 83 f8 05 0f 84 90 00 00 00 56 59 e8 44 ff ff ff 83 f8 06 75 0c 56 59 e8 64 ff ff ff 83 f8 0a 74 } //1
		$a_01_1 = {55 73 61 53 68 6f 68 64 69 } //1 UsaShohdi
		$a_01_2 = {45 76 65 6e 20 41 6d 65 72 69 63 61 20 69 73 20 6e 6f 74 20 61 20 66 72 65 65 20 77 6f 72 6c 64 } //1 Even America is not a free world
		$a_01_3 = {49 72 61 71 20 61 6e 64 20 77 68 61 74 20 69 73 20 68 61 70 70 65 6e 65 64 20 74 68 65 72 65 } //1 Iraq and what is happened there
		$a_01_4 = {6e 6f 20 6f 6e 65 20 73 61 79 20 61 6e 79 74 68 69 6e 67 20 61 62 6f 75 74 20 49 73 72 61 65 6c } //1 no one say anything about Israel
		$a_01_5 = {46 75 63 6b 20 79 6f 75 } //1 Fuck you
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}