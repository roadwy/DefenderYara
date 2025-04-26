
rule Trojan_AndroidOS_FakeVoice_A{
	meta:
		description = "Trojan:AndroidOS/FakeVoice.A,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {50 49 43 4b 5f 43 4f 4e 54 41 43 54 } //1 PICK_CONTACT
		$a_01_1 = {65 72 72 6f 72 5f 69 73 72 61 65 6c } //1 error_israel
		$a_01_2 = {70 72 69 63 65 5f 74 69 74 6c 65 } //1 price_title
		$a_01_3 = {56 6f 69 63 65 43 68 61 6e 67 65 2f 56 6f 69 63 65 43 68 61 6e 67 65 49 4c 2f 4d 61 69 6e 41 63 74 69 76 69 74 79 } //1 VoiceChange/VoiceChangeIL/MainActivity
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}