
rule Trojan_AndroidOS_Rootnik_A{
	meta:
		description = "Trojan:AndroidOS/Rootnik.A,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {2f 64 61 74 61 2f 6c 6f 63 61 6c 2f 7a 65 6e 2f 69 6e 6a 65 63 74 2e 61 70 6b } //1 /data/local/zen/inject.apk
		$a_00_1 = {53 75 52 65 63 65 69 76 65 72 20 2d 2d 20 } //1 SuReceiver -- 
		$a_00_2 = {63 6f 70 79 20 6c 69 62 77 6f 72 6d 5f 6b 75 } //1 copy libworm_ku
		$a_00_3 = {68 61 73 53 75 52 6f 6f 74 } //1 hasSuRoot
		$a_00_4 = {49 6e 6a 65 63 74 20 6d 61 69 6e 20 70 69 64 } //1 Inject main pid
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}