
rule Ransom_Win64_Ryuk_PB_MTB{
	meta:
		description = "Ransom:Win64/Ryuk.PB!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 8a 02 45 03 cb 41 28 00 4d 8d 52 04 4d 03 c3 41 83 f9 0c 72 ea } //01 00 
		$a_01_1 = {41 8b c0 45 03 c7 99 f7 fe 48 63 c2 8a 4c 84 20 41 28 09 4d 03 cf 45 3b c2 7c e5 } //01 00 
		$a_01_2 = {41 8b c2 41 ff c2 99 41 f7 fb 48 63 ca 0f b7 14 8b 66 41 29 10 4d 8d 40 02 45 3b d1 7c e2 } //01 00 
		$a_01_3 = {41 0f b6 08 4c 03 c6 8b c1 83 e1 0f 48 c1 e8 04 42 8a 04 10 88 42 ff 42 8a 04 11 88 02 48 8d 52 02 4c 2b ce 75 da } //00 00 
	condition:
		any of ($a_*)
 
}