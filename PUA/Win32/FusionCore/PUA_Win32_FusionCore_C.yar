
rule PUA_Win32_FusionCore_C{
	meta:
		description = "PUA:Win32/FusionCore.C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 0a 00 00 "
		
	strings :
		$a_01_0 = {46 55 53 5f 53 48 4f 57 4f 46 46 45 52 53 } //1 FUS_SHOWOFFERS
		$a_01_1 = {46 55 53 5f 49 4e 49 54 44 4c 4c } //1 FUS_INITDLL
		$a_01_2 = {46 55 53 5f 44 45 43 4c 49 4e 45 4f 46 46 45 52 } //1 FUS_DECLINEOFFER
		$a_01_3 = {46 55 53 5f 47 45 54 44 4c 4c 53 54 41 54 45 } //1 FUS_GETDLLSTATE
		$a_01_4 = {46 55 53 5f 4e 45 58 54 4f 46 46 45 52 } //1 FUS_NEXTOFFER
		$a_01_5 = {46 55 53 5f 49 4e 53 54 41 4c 4c 4f 46 46 45 52 53 } //1 FUS_INSTALLOFFERS
		$a_01_6 = {46 55 53 5f 46 52 45 45 44 4c 4c } //1 FUS_FREEDLL
		$a_01_7 = {46 55 53 5f 4f 46 46 45 52 5f 44 45 46 41 55 4c 54 5f 43 41 50 54 49 4f 4e } //1 FUS_OFFER_DEFAULT_CAPTION
		$a_01_8 = {46 55 53 5f 4f 46 46 45 52 5f 44 45 53 43 } //1 FUS_OFFER_DESC
		$a_01_9 = {46 55 53 5f 4f 46 46 45 52 5f 43 41 50 54 49 4f 4e 5f 50 52 45 46 49 58 } //1 FUS_OFFER_CAPTION_PREFIX
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=3
 
}