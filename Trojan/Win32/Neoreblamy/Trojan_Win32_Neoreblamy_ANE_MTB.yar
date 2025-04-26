
rule Trojan_Win32_Neoreblamy_ANE_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.ANE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 0d 00 00 "
		
	strings :
		$a_01_0 = {79 42 49 77 45 61 65 65 4f 55 46 62 4f 72 66 4d 4f 61 54 44 47 6c 44 6f 56 4b 6f 78 } //1 yBIwEaeeOUFbOrfMOaTDGlDoVKox
		$a_01_1 = {41 42 53 4d 76 4e 73 69 77 63 6e 68 4a 55 76 46 4f 6e 58 4b 49 52 61 4a 65 67 44 6e 51 74 } //1 ABSMvNsiwcnhJUvFOnXKIRaJegDnQt
		$a_01_2 = {78 63 57 6b 57 75 43 77 50 59 65 64 75 67 43 62 68 47 68 4c 61 45 44 57 51 66 6a 6f 44 } //1 xcWkWuCwPYedugCbhGhLaEDWQfjoD
		$a_01_3 = {77 6a 55 67 41 65 49 43 6a 6e 54 62 69 45 54 41 4c 68 45 63 65 77 57 41 56 43 53 6d 45 } //1 wjUgAeICjnTbiETALhEcewWAVCSmE
		$a_01_4 = {6e 63 43 4e 52 4c 57 46 4e 48 51 6e 70 72 74 6b 75 } //1 ncCNRLWFNHQnprtku
		$a_01_5 = {5a 70 54 7a 63 46 73 45 4b 69 78 78 65 78 71 6a 61 46 50 64 74 65 72 } //1 ZpTzcFsEKixxexqjaFPdter
		$a_01_6 = {53 4f 56 65 55 5a 42 49 } //1 SOVeUZBI
		$a_01_7 = {70 74 5a 62 48 53 4b 6e 62 6d 50 55 69 70 45 46 49 6d 47 } //1 ptZbHSKnbmPUipEFImG
		$a_01_8 = {70 5a 69 45 4f 7a 6e 4d 73 54 67 64 64 68 77 55 } //1 pZiEOznMsTgddhwU
		$a_01_9 = {74 42 4e 79 7a 49 49 59 54 44 63 51 52 57 46 56 6b 6f } //1 tBNyzIIYTDcQRWFVko
		$a_01_10 = {77 77 72 66 73 74 61 47 58 53 49 78 6b 64 66 59 45 4a 69 58 41 54 42 54 49 } //1 wwrfstaGXSIxkdfYEJiXATBTI
		$a_01_11 = {4b 75 6a 72 42 53 4f 77 47 44 54 42 45 69 4b 42 6f 6c 54 50 77 4c } //1 KujrBSOwGDTBEiKBolTPwL
		$a_01_12 = {77 76 55 41 79 4a 41 44 73 74 52 73 51 65 44 63 76 } //1 wvUAyJADstRsQeDcv
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1) >=13
 
}