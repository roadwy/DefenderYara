
rule Trojan_Win64_Lazy_LR_MTB{
	meta:
		description = "Trojan:Win64/Lazy.LR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 0f b6 c6 32 04 0b 88 04 0e 45 02 f7 48 ff c1 48 3b cf } //10
		$a_01_1 = {45 6b c0 21 48 8d 40 01 0f be d1 0f b6 08 41 33 d2 44 03 c2 84 c9 } //20
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*20) >=30
 
}