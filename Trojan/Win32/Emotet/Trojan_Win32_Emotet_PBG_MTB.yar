
rule Trojan_Win32_Emotet_PBG_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PBG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {8a 04 0f 03 c2 33 d2 f7 35 90 01 04 8a 04 0a 8b 54 24 90 01 01 32 04 13 8b 54 24 90 01 01 88 04 13 90 00 } //1
		$a_81_1 = {6b 7e 65 7b 25 62 50 33 7e 66 41 42 32 4c 43 57 56 43 56 4a 73 7a 4a 6c 40 6b 47 4a 66 46 48 7e 36 46 7e 40 33 7c 2a 30 52 32 25 6d 25 65 30 56 44 73 4e 54 6d 59 41 73 4f 7e 65 59 39 41 67 33 } //1 k~e{%bP3~fAB2LCWVCVJszJl@kGJfFH~6F~@3|*0R2%m%e0VDsNTmYAsO~eY9Ag3
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}