
rule Trojan_Win64_PixelStealer_LR_MTB{
	meta:
		description = "Trojan:Win64/PixelStealer.LR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 c1 e8 39 4d 8d 41 f0 49 21 d0 42 88 04 09 42 88 44 01 10 48 8b 45 00 48 8d 0c bf 48 89 c2 48 29 ca 4c 8b 44 24 38 4f 8d 0c 89 } //20
		$a_03_1 = {49 29 c8 49 89 d1 49 29 c9 4d 31 c1 49 21 e9 49 83 f9 10 0f 82 ?? ?? ?? ?? 48 8d 0c 92 44 0f b6 04 16 48 c1 e8 39 4c 8d 4a f0 49 21 e9 88 04 16 } //10
	condition:
		((#a_01_0  & 1)*20+(#a_03_1  & 1)*10) >=30
 
}