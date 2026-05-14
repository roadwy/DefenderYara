
rule _#PUA_Block_OpenInstaller{
	meta:
		description = "!#PUA:Block:OpenInstaller,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {67 65 74 5f 6f 66 66 65 72 73 } //1 get_offers
		$a_01_1 = {73 68 6f 77 6e 4f 66 66 65 72 73 } //1 shownOffers
		$a_01_2 = {61 63 63 65 70 74 65 64 4f 66 66 65 72 73 } //1 acceptedOffers
		$a_01_3 = {6d 61 72 6b 65 74 2e 6f 69 63 64 6e 2e 63 6f 6d } //1 market.oicdn.com
		$a_00_4 = {4f 00 70 00 65 00 6e 00 49 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 } //1 OpenInstall
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}
rule _#PUA_Block_OpenInstaller_2{
	meta:
		description = "!#PUA:Block:OpenInstaller,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_80_0 = {43 61 6e 63 65 6c 4f 66 66 65 72 54 68 72 65 61 64 73 } //CancelOfferThreads  1
		$a_80_1 = {50 61 67 65 4f 66 66 65 72 } //PageOffer  1
		$a_80_2 = {73 68 6f 77 6e 4f 66 66 65 72 73 } //shownOffers  1
		$a_80_3 = {70 72 65 70 61 72 65 64 4f 66 66 65 72 73 } //preparedOffers  1
		$a_80_4 = {49 73 4f 66 66 65 72 54 68 72 65 61 64 52 75 6e 6e 69 6e 67 } //IsOfferThreadRunning  1
		$a_80_5 = {64 69 73 61 62 6c 65 44 79 6e 61 6d 69 63 4f 66 66 65 72 73 } //disableDynamicOffers  1
		$a_80_6 = {65 72 72 2e 63 6c 6f 69 6e 73 2e 63 6f 6d } //err.cloins.com  1
		$a_80_7 = {73 74 2e 63 6c 6f 69 6e 73 2e 63 6f 6d } //st.cloins.com  1
		$a_80_8 = {61 66 74 65 72 64 61 77 6e 2e 63 6f 6d } //afterdawn.com  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1) >=9
 
}