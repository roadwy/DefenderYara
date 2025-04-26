
rule Trojan_BAT_Dothetuk_GZZ_MTB{
	meta:
		description = "Trojan:BAT/Dothetuk.GZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_03_0 = {11 08 72 43 00 00 70 28 ?? ?? ?? 0a 72 75 00 00 70 28 ?? ?? ?? 06 28 ?? ?? ?? 06 13 01 } //5
		$a_01_1 = {11 03 11 01 16 73 0e 00 00 0a 13 09 20 00 00 00 00 } //5
		$a_80_2 = {6b 4d 4e 6b 77 54 6b 6d 34 6c 55 78 4f 64 65 75 4a 35 51 69 47 41 3d 3d } //kMNkwTkm4lUxOdeuJ5QiGA==  1
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5+(#a_80_2  & 1)*1) >=11
 
}