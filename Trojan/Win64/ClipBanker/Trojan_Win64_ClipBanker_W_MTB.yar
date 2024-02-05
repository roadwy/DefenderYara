
rule Trojan_Win64_ClipBanker_W_MTB{
	meta:
		description = "Trojan:Win64/ClipBanker.W!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {48 8b 05 ce 9b 03 00 48 83 f8 2a 72 90 01 01 48 83 f8 10 48 c7 05 90 01 04 2a 00 00 00 48 8b de 48 8d 15 90 01 04 48 0f 43 1d 8f 9b 03 00 41 b8 2a 00 00 00 48 8b cb e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}