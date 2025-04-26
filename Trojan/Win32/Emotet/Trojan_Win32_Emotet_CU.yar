
rule Trojan_Win32_Emotet_CU{
	meta:
		description = "Trojan:Win32/Emotet.CU,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {2b 70 32 7a 64 58 30 53 44 31 4b 4d 4c 39 3d 46 43 6d 72 } //2 +p2zdX0SD1KML9=FCmr
		$a_01_1 = {4c 4f 49 49 63 63 41 51 2e 70 64 62 } //2 LOIIccAQ.pdb
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}