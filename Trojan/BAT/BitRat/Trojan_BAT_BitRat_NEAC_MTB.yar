
rule Trojan_BAT_BitRat_NEAC_MTB{
	meta:
		description = "Trojan:BAT/BitRat.NEAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 04 00 00 "
		
	strings :
		$a_01_0 = {61 66 33 66 65 65 62 34 2d 31 63 37 31 2d 34 63 34 38 2d 38 37 38 64 2d 31 36 39 66 33 33 31 35 62 38 35 35 } //5 af3feeb4-1c71-4c48-878d-169f3315b855
		$a_01_1 = {6d 69 41 65 65 63 2e 65 78 65 } //2 miAeec.exe
		$a_01_2 = {53 6d 61 72 74 41 73 73 65 6d 62 6c 79 2e 48 6f 75 73 65 4f 66 43 61 72 64 73 } //1 SmartAssembly.HouseOfCards
		$a_01_3 = {73 65 74 5f 43 72 65 61 74 65 4e 6f 57 69 6e 64 6f 77 } //1 set_CreateNoWindow
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=9
 
}