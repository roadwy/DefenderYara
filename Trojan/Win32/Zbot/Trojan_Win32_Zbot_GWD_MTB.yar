
rule Trojan_Win32_Zbot_GWD_MTB{
	meta:
		description = "Trojan:Win32/Zbot.GWD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_80_0 = {31 30 37 2e 36 35 2e 37 39 2e 36 35 } //107.65.79.65  1
		$a_01_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
		$a_80_2 = {67 66 75 6f 75 71 75 67 79 73 67 69 64 73 6d 79 74 } //gfuouqugysgidsmyt  1
		$a_80_3 = {71 78 6a 69 76 65 76 79 76 65 69 } //qxjivevyvei  1
		$a_80_4 = {74 69 66 76 77 6e 6b 62 69 61 6b 6d 63 } //tifvwnkbiakmc  1
		$a_80_5 = {6d 62 75 65 74 62 71 6a 68 67 6a 79 69 } //mbuetbqjhgjyi  1
		$a_80_6 = {6f 69 75 72 6a 66 73 69 73 6b 64 77 6d 69 67 } //oiurjfsiskdwmig  1
		$a_80_7 = {61 77 75 63 6f 62 74 73 74 } //awucobtst  1
	condition:
		((#a_80_0  & 1)*1+(#a_01_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1) >=8
 
}