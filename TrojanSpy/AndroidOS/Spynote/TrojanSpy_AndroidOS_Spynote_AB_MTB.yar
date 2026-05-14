
rule TrojanSpy_AndroidOS_Spynote_AB_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Spynote.AB!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2e 61 70 70 64 2e 69 6e 73 74 6c 6c 2e 6c 6f 61 64 2e 61 63 74 69 6f 6e 2e 52 6f 6f 74 6c 65 73 73 53 61 69 50 69 42 72 6f 61 64 63 61 73 74 52 65 63 65 69 76 65 72 } //1 com.appd.instll.load.action.RootlessSaiPiBroadcastReceiver
		$a_01_1 = {82 3a a8 0a 0a 02 87 aa 82 9b a8 0b 0b 00 87 bb 6e 30 09 02 ad 0b 0a 0a 71 10 2e 02 0a 00 0a 0b 13 0c c8 00 37 cb 13 00 71 10 37 02 0a 00 0a 0b b0 b5 71 10 36 02 0a 00 0a 0b b0 b6 71 10 30 02 0a 00 0a 0a b0 a7 d8 04 04 01 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}