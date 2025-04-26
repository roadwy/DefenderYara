
rule Trojan_Win32_Zbot_EP_MTB{
	meta:
		description = "Trojan:Win32/Zbot.EP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_80_0 = {55 6e 69 76 73 61 6d 75 72 69 6e 65 72 63 61 6e 78 } //Univsamurinercanx  1
		$a_80_1 = {6d 33 32 6d 78 46 56 54 62 6b } //m32mxFVTbk  1
		$a_80_2 = {71 78 77 65 64 61 6d 72 64 61 65 6d 78 } //qxwedamrdaemx  1
		$a_80_3 = {6b 6d 73 63 6d 65 66 64 77 71 77 } //kmscmefdwqw  1
		$a_80_4 = {44 65 61 6e 75 6d 73 65 6e 6d 61 77 7a 63 } //Deanumsenmawzc  1
		$a_80_5 = {65 72 77 72 64 65 73 78 71 77 } //erwrdesxqw  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=6
 
}