
rule Trojan_Win32_Zenpak_ASAB_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.ASAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_03_0 = {55 89 e5 8a 45 0c 8a 4d 08 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 30 c8 0f b6 c0 5d c3 } //5
		$a_01_1 = {78 00 6d 00 68 00 46 00 6f 00 77 00 6c 00 62 00 72 00 69 00 6e 00 67 00 61 00 6c 00 6c 00 6b 00 69 00 6e 00 64 00 6d 00 6f 00 72 00 6e 00 69 00 6e 00 67 00 61 00 6e 00 64 00 } //1 xmhFowlbringallkindmorningand
		$a_01_2 = {6d 00 69 00 64 00 73 00 74 00 67 00 72 00 65 00 65 00 6e 00 66 00 72 00 75 00 69 00 74 00 66 00 75 00 6c 00 79 00 65 00 61 00 72 00 73 00 68 00 69 00 6d 00 6f 00 74 00 } //1 midstgreenfruitfulyearshimot
		$a_01_3 = {6d 00 61 00 6c 00 65 00 6d 00 61 00 79 00 73 00 65 00 61 00 61 00 69 00 72 00 55 00 66 00 65 00 6d 00 61 00 6c 00 65 00 64 00 61 00 72 00 6b 00 6e 00 65 00 73 00 73 00 78 00 56 00 } //1 malemayseaairUfemaledarknessxV
		$a_01_4 = {48 00 77 00 6f 00 6e 00 2e 00 74 00 7a 00 6a 00 69 00 73 00 6e 00 2e 00 74 00 6f 00 76 00 65 00 72 00 2e 00 68 00 65 00 72 00 62 00 67 00 72 00 65 00 61 00 74 00 65 00 72 00 33 00 66 00 6c 00 79 00 } //1 Hwon.tzjisn.tover.herbgreater3fly
		$a_01_5 = {71 00 63 00 72 00 65 00 61 00 74 00 75 00 72 00 65 00 64 00 6f 00 65 00 73 00 6e 00 2e 00 74 00 58 00 34 00 63 00 } //1 qcreaturedoesn.tX4c
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}