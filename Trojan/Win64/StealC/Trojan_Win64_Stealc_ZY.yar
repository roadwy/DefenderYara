
rule Trojan_Win64_Stealc_ZY{
	meta:
		description = "Trojan:Win64/Stealc.ZY,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //1
		$a_03_1 = {48 8d 54 24 28 48 8d 4d 98 e8 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 0f b7 c8 81 e9 19 04 00 00 74 14 83 e9 09 74 0f 83 e9 01 74 0a 83 e9 1c 74 05 83 f9 04 75 08 33 c9 ff 15 } //10
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*10) >=11
 
}