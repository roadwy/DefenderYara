
rule Trojan_BAT_ClipBanker_DAJ_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.DAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {93 e3 cf e6 60 69 57 e4 e0 33 4d f2 c0 ee 7c f8 7d 6e 3a 77 59 64 8e 27 ed 73 a6 12 76 18 f5 49 21 b0 d4 04 dc 3d 99 d1 05 7d cb 52 d4 02 6d 44 75 a7 a3 ae 0a 61 ba 01 f4 4b db 02 ad } //02 00 
		$a_01_1 = {c4 81 eb df b6 53 9a df 2b e9 cb f8 35 e5 66 4a bd 39 72 d2 03 ab ff dc ab 4d 3a d6 00 82 0b 88 c8 33 07 cd 32 c0 2d 6b 6d 70 53 32 e8 3b 1d c9 } //00 00 
	condition:
		any of ($a_*)
 
}