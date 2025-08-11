
rule Trojan_Win64_CoinStealer_SX_MTB{
	meta:
		description = "Trojan:Win64/CoinStealer.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_03_0 = {49 8b 0e 4c 8d 45 60 48 8d 95 c0 00 00 00 ff 15 ?? ?? ?? ?? 0f 57 c0 0f 11 85 c0 00 00 00 48 8b df 48 89 9d d0 00 00 00 41 bc 0f 00 00 00 } //5
		$a_01_1 = {48 8b d8 48 8d 8d 28 02 00 00 48 83 bd 40 02 00 00 0f 48 0f 47 8d 28 02 00 00 48 ff c7 44 38 24 39 75 f7 48 8d 95 28 02 00 00 48 83 bd 40 02 00 00 0f 48 0f 47 95 28 02 00 00 4c 89 64 24 20 4c 8d 8d a8 01 00 00 44 8b c7 48 8b cb } //3
		$a_03_2 = {f3 0f 6f 8c 08 ?? ?? ?? ?? f3 0f 6f 84 05 a0 00 00 00 0f 57 c8 f3 0f 7f 8c 05 a0 00 00 00 48 83 c0 10 48 83 f8 70 7c d8 } //2
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*3+(#a_03_2  & 1)*2) >=10
 
}