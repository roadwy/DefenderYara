
rule Trojan_BAT_SpyNoon_AMAD_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.AMAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {a2 13 06 72 90 01 01 01 00 70 72 90 01 01 02 00 70 72 90 01 01 01 00 70 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 13 07 11 07 09 11 05 14 14 11 06 6f 90 01 01 00 00 0a 26 2a 90 00 } //1
		$a_80_1 = {23 23 43 23 23 72 23 65 23 23 61 23 74 23 23 65 23 49 23 23 6e 23 73 23 23 74 23 61 23 23 6e 23 63 23 23 65 23 } //##C##r#e##a#t##e#I##n#s##t#a##n#c##e#  1
		$a_80_2 = {44 79 6e 61 6d 69 63 50 72 6f 70 65 72 74 79 4f 62 6a 65 63 74 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //DynamicPropertyObject.Properties.Resources  1
		$a_80_3 = {53 79 73 74 65 6d 2e 4e 65 74 2e 53 6f 63 6b 65 74 73 } //System.Net.Sockets  1
	condition:
		((#a_03_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}