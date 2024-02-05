
rule Trojan_Win64_ClipBanker_U_MTB{
	meta:
		description = "Trojan:Win64/ClipBanker.U!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {48 83 ec 20 48 89 6c 24 18 48 8d 6c 24 18 48 8d 05 65 a2 01 00 0f 1f 44 00 00 e8 90 01 02 f2 ff 48 89 44 24 10 bb 01 00 00 00 e8 90 01 02 f8 ff 31 c0 48 8d 1d 4b 8f 03 00 0f 1f 00 e8 90 01 02 f5 ff 31 c0 48 8d 1d 42 8f 03 00 e8 90 01 02 f5 ff 48 8b 44 24 10 e8 90 01 02 f8 ff 48 8b 6c 24 18 48 83 c4 20 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}