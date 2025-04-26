
rule Trojan_AndroidOS_Legana_A{
	meta:
		description = "Trojan:AndroidOS/Legana.A,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_00_0 = {53 74 61 6b 5f 79 45 78 79 2d 65 4c 74 21 50 77 } //1 Stak_yExy-eLt!Pw
		$a_00_1 = {cc af 4b 1b 0b 94 7a 79 eb 4a 51 49 4c 85 49 8c 6d d6 29 25 74 c0 23 b2 fa a6 7b 50 2a 0d 38 25 } //1
		$a_00_2 = {73 61 66 65 73 79 73 } //1 safesys
		$a_00_3 = {65 74 63 2f 2e 64 68 63 70 63 64 } //1 etc/.dhcpcd
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=3
 
}