
rule Trojan_Win32_Emotet_RTH_MTB{
	meta:
		description = "Trojan:Win32/Emotet.RTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_80_0 = {37 6b 52 40 58 40 42 75 79 34 37 58 2a 75 5a 6d 54 58 5e 67 35 50 65 2a 3e 47 33 31 77 41 6a 24 42 71 5f 59 69 53 72 46 4a 74 53 36 31 34 51 29 63 26 } //7kR@X@Buy47X*uZmTX^g5Pe*>G31wAj$Bq_YiSrFJtS614Q)c&  01 00 
		$a_03_1 = {0d 00 10 00 00 50 8b 55 b0 52 6a 00 6a ff ff 15 90 01 04 89 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Emotet_RTH_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.RTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_81_0 = {64 2b 25 37 46 4d 38 4d 55 65 53 48 30 5f 78 48 34 29 4c 71 46 6c 36 44 5e 44 37 77 73 71 6b 34 4a 78 69 50 71 30 56 6d 40 24 3f 38 6d 4d 26 53 6a 43 3c 58 51 39 66 37 4c 74 2b 4b 62 3e 53 52 4a 51 39 } //01 00  d+%7FM8MUeSH0_xH4)LqFl6D^D7wsqk4JxiPq0Vm@$?8mM&SjC<XQ9f7Lt+Kb>SRJQ9
		$a_03_1 = {2b d1 2b 15 90 01 04 03 15 90 01 04 8b 4d 90 01 01 0f b6 14 11 8b 4d 90 01 01 0f b6 04 01 33 c2 8b 4d 90 01 01 2b 0d 90 01 04 8b 55 90 01 01 88 04 0a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Emotet_RTH_MTB_3{
	meta:
		description = "Trojan:Win32/Emotet.RTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {7a 5a 24 62 65 28 33 62 52 3e 78 67 25 69 6c 37 4d 72 3e 75 6a 75 6d 4e 38 64 24 65 75 24 6a 39 58 5e 32 40 4b 70 6a 2b 34 33 42 77 62 53 41 30 26 61 4d 65 6b 28 7a 75 42 4a 26 45 29 23 5a 78 6c 66 33 31 4d 28 5a 39 4f 47 3f 6d 32 3e 49 4e 39 73 77 62 68 53 74 26 78 6c 5e } //01 00  zZ$be(3bR>xg%il7Mr>ujumN8d$eu$j9X^2@Kpj+43BwbSA0&aMek(zuBJ&E)#Zxlf31M(Z9OG?m2>IN9swbhSt&xl^
		$a_03_1 = {83 c2 01 89 55 90 01 01 8b 90 01 02 3b 90 01 02 73 90 02 12 03 90 02 05 8a 02 88 01 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Emotet_RTH_MTB_4{
	meta:
		description = "Trojan:Win32/Emotet.RTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_80_0 = {52 79 75 6d 61 7a 71 75 44 6d 44 62 69 4f 6a 49 55 35 54 3c 30 48 37 52 67 47 4e 63 5f 6d 55 2a 7a 37 40 40 35 6f 58 59 76 26 6d 28 52 76 54 4c 66 5f 73 50 67 21 44 38 36 42 24 53 6f 33 6e 68 54 63 78 69 4f 4c 57 71 4a 31 70 30 55 62 25 40 26 77 44 23 51 41 57 59 79 55 42 28 5a 4d 61 56 5e 79 47 3c 35 51 53 5e 47 67 79 33 6b 78 44 62 } //RyumazquDmDbiOjIU5T<0H7RgGNc_mU*z7@@5oXYv&m(RvTLf_sPg!D86B$So3nhTcxiOLWqJ1p0Ub%@&wD#QAWYyUB(ZMaV^yG<5QS^Ggy3kxDb  01 00 
		$a_03_1 = {83 c4 04 f7 d8 50 ff 15 90 01 04 89 45 90 01 01 eb 16 6a 40 68 00 30 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}