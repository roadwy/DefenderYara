
rule Trojan_WinNT_Adwind_AS_bit{
	meta:
		description = "Trojan:WinNT/Adwind.AS!bit,SIGNATURE_TYPE_JAVAHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {7e 4c 77 2f 6d 61 6e 69 6e 74 68 65 73 6b 79 6d 61 6e 69 6e 74 68 65 73 6b 79 6d 61 6e 69 6e 74 68 65 73 6b 79 6d 61 6e 69 6e 74 68 65 73 6b 79 6d 61 6e 69 6e 74 68 65 73 6b 79 6d 61 6e 69 6e 74 68 65 73 6b 79 6d 6d 61 6e 69 6e 74 68 65 73 6b 79 6d 61 6e 69 6e 74 68 65 73 6b 79 6d 61 6e 69 6e 74 68 65 73 6b 79 6d 61 6e 69 6e 74 68 65 73 6b 79 61 6e 69 6e 74 68 65 73 6b 79 } //1 ~Lw/manintheskymanintheskymanintheskymanintheskymanintheskymanintheskymmanintheskymanintheskymanintheskymanintheskyaninthesky
	condition:
		((#a_01_0  & 1)*1) >=1
 
}