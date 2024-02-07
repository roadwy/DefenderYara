
rule TrojanDropper_BAT_Bepush_D{
	meta:
		description = "TrojanDropper:BAT/Bepush.D,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 45 6d 72 65 5c 44 65 73 6b 74 6f 70 5c 44 6f 77 6e 6c 6f 61 64 5c 57 69 6e 64 6f 77 73 46 6f 72 6d 73 41 70 70 6c 69 63 61 74 69 6f 6e 35 5c 6f 62 6a 5c 44 65 62 75 67 5c 46 6c 61 73 68 47 75 6e 63 65 6c 6c 65 2e 70 64 62 00 } //01 00 
		$a_01_1 = {6f 72 6d 73 41 70 70 6c 69 63 61 74 69 6f 6e 35 2e 46 6f 72 6d 31 2e 72 65 73 6f 75 72 63 65 73 00 46 6c 61 73 68 47 75 6e 63 65 6c 6c 65 2e 50 } //00 00  牯獭灁汰捩瑡潩㕮䘮牯ㅭ爮獥畯捲獥䘀慬桳畇据汥敬倮
	condition:
		any of ($a_*)
 
}