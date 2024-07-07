
rule Trojan_Win64_Fsysna_NFC_MTB{
	meta:
		description = "Trojan:Win64/Fsysna.NFC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {75 e2 48 8b 84 24 90 01 04 89 44 24 28 48 8d 84 24 90 01 04 48 89 44 24 20 41 b9 90 01 04 45 33 c0 48 8d 15 a9 d0 02 00 90 00 } //5
		$a_01_1 = {43 6d 4e 74 5a 43 35 6c 65 47 55 67 4c 32 4d 67 } //1 CmNtZC5leGUgL2Mg
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}