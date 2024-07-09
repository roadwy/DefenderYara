
rule Trojan_Win64_CobaltStrike_E_ibt{
	meta:
		description = "Trojan:Win64/CobaltStrike.E!ibt,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {66 41 5d 5a } //1 fA]Z
		$a_00_1 = {59 47 40 4a 47 5c } //1 YG@JG\
		$a_00_2 = {5d 57 5d 40 4f 5a 47 58 4b } //1 ]W]@OZGXK
		$a_00_3 = {7c 5a 42 7b 5d 4b 5c 7a 46 5c 4b 4f 4a 7d 5a 4f 5c 5a } //1 |ZB{]K\zF\KOJ}ZO\Z
		$a_00_4 = {4d 5a 41 52 55 48 89 e5 } //1
		$a_03_5 = {8e 4e 0e ec 74 ?? 81 7c ?? ?? aa fc 0d 7c 74 ?? 81 7c ?? ?? 54 ca af 91 74 ?? 81 7c ?? ?? 1b c6 46 79 74 ?? 81 7c ?? ?? fc a4 53 07 74 ?? 81 7c ?? ?? 04 49 32 d3 0f } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_03_5  & 1)*1) >=6
 
}