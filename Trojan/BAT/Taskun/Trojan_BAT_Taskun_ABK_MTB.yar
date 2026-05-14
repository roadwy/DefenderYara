
rule Trojan_BAT_Taskun_ABK_MTB{
	meta:
		description = "Trojan:BAT/Taskun.ABK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {1f 0d 13 04 38 77 ff ff ff 02 28 ?? 00 00 0a 0b 11 06 20 b6 01 00 00 93 20 e5 42 00 00 59 13 04 38 5b ff ff ff 02 28 ?? 00 00 0a 0b 1f 0d 13 04 38 4b ff ff ff 02 28 ?? 00 00 0a 0b 1f 0d 13 04 38 3b ff ff ff 06 17 58 0a 03 25 5a } //5
		$a_03_1 = {02 8c 03 00 00 1b 03 04 6f ?? 00 00 0a 0b 1d 13 04 38 5a ff ff ff } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}