
rule Trojan_AndroidOS_Fakeplayer{
	meta:
		description = "Trojan:AndroidOS/Fakeplayer,SIGNATURE_TYPE_DEXHSTR_EXT,0d 00 0d 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {0c d0 9f d0 be d0 b4 d0 be d0 b6 d0 b4 d0 b8 d1 82 d0 b5 2e 2e 2e 00 } //01 00 
		$a_01_1 = {d1 80 d1 81 d0 be d0 bd d0 b0 d0 bb d1 8c d0 bd d0 be d0 b3 d0 be 20 d0 ba d0 bb d1 8e d1 87 d0 b0 2e 2e 2e 00 } //02 00 
		$a_01_2 = {63 61 6e 77 65 } //05 00  canwe
		$a_01_3 = {28 4c 6f 72 67 2f 6d 65 2f 61 6e 64 72 6f 69 64 61 70 70 6c 69 63 61 74 69 6f 6e 31 2f 4d 6f 76 69 65 50 6c 61 79 65 72 3b 00 } //05 00  䰨牯⽧敭愯摮潲摩灡汰捩瑡潩ㅮ䴯癯敩汐祡牥;
		$a_01_4 = {2f 74 65 6c 65 70 68 6f 6e 79 2f 53 6d 73 4d 61 6e 61 67 65 72 3b } //00 00  /telephony/SmsManager;
	condition:
		any of ($a_*)
 
}