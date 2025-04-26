
rule Trojan_Win32_CobaltStrike_E_ibt{
	meta:
		description = "Trojan:Win32/CobaltStrike.E!ibt,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {66 41 5d 5a } //1 fA]Z
		$a_00_1 = {59 47 40 4a 47 5c } //1 YG@JG\
		$a_00_2 = {5d 57 5d 40 4f 5a 47 58 4b } //1 ]W]@OZGXK
		$a_00_3 = {4d 5a 52 45 e8 00 00 00 } //1
		$a_03_4 = {8e 4e 0e ec 74 ?? 81 ?? ?? aa fc 0d 7c 74 ?? 81 ?? ?? 54 ca af 91 74 ?? 81 ?? ?? 1b c6 46 79 74 ?? 81 ?? ?? fc a4 53 07 74 ?? 81 ?? ?? 04 49 32 d3 0f } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}