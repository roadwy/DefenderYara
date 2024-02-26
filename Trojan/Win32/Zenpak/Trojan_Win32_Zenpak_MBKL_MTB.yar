
rule Trojan_Win32_Zenpak_MBKL_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.MBKL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 61 70 69 6d 6f 68 69 62 6f 7a 61 79 6f 63 65 78 6f 6a 69 6b 65 79 65 66 61 20 6b 61 63 75 6a 61 77 65 6d 6f 6a 69 6d 65 6e 61 64 61 6e 65 64 6f 6d 00 00 67 6f 63 75 79 65 6e 61 7a 65 74 6f 6a 61 62 6f 70 65 68 65 77 69 66 00 6c 65 77 61 79 69 76 65 73 75 72 65 6a 75 6d 65 77 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Zenpak_MBKL_MTB_2{
	meta:
		description = "Trojan:Win32/Zenpak.MBKL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {6d 69 66 69 70 65 73 61 6e 61 68 65 77 6f 78 65 7a 75 73 75 77 6f 70 61 78 65 78 6f 63 } //01 00  mifipesanahewoxezusuwopaxexoc
		$a_01_1 = {78 61 62 6f 73 69 74 69 78 61 62 6f 78 6f 6a 65 62 65 6b 65 79 65 79 65 78 61 6b 69 6e 69 6b 6f 6a 61 73 75 70 69 7a 6f 66 61 66 65 68 61 74 6f 66 69 6b 65 6b 61 64 69 68 69 73 65 6b 61 63 75 6a 75 6d 6f 6b 75 73 6f 78 75 73 6f 73 61 6d 6f } //01 00  xabositixaboxojebekeyeyexakinikojasupizofafehatofikekadihisekacujumokusoxusosamo
		$a_01_2 = {79 61 77 61 67 6f 62 65 64 75 68 61 66 75 72 75 74 61 67 75 6c 65 6c } //01 00  yawagobeduhafurutagulel
		$a_01_3 = {68 75 66 6f 66 65 68 69 7a 75 } //00 00  hufofehizu
	condition:
		any of ($a_*)
 
}