
rule Trojan_Win64_AridWrangler_A{
	meta:
		description = "Trojan:Win64/AridWrangler.A,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_03_0 = {f2 0f 11 44 24 40 f2 0f 10 44 24 40 f2 0f 59 c6 e8 ?? ?? ?? 00 8b 83 1a f6 03 00 3b 05 ?? ?? ?? 00 f2 0f 11 44 24 40 74 } //10
		$a_03_1 = {f2 0f 10 4c 24 40 8b 83 1a f6 03 00 3b 05 ?? ?? ?? 00 f2 0f 59 ce f2 0f 11 4c 24 40 74 } //10
		$a_01_2 = {00 00 00 48 8b d8 eb 00 00 00 00 } //1
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10+(#a_01_2  & 1)*1) >=11
 
}