
rule Trojan_BAT_Heracles_AMCO_MTB{
	meta:
		description = "Trojan:BAT/Heracles.AMCO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {55 00 58 00 4a 00 5a 00 68 00 77 00 60 00 5c 00 73 00 58 00 75 00 58 00 68 00 68 00 71 00 55 00 7c 00 3f 00 4b 00 56 00 3d 00 7d 00 55 00 50 00 3c 00 6b 00 4b 00 7d 00 3b 00 7d 00 6b 00 4f 00 3e 00 75 00 7e 00 60 00 51 00 76 00 36 00 75 00 39 00 59 00 74 00 54 00 77 00 6f 00 7c 00 3b 00 4b 00 5a 00 5d 00 } //3 UXJZhw`\sXuXhhqU|?KV=}UP<kK};}kO>u~`Qv6u9YtTwo|;KZ]
		$a_01_1 = {79 00 60 00 3f 00 59 00 39 00 3e 00 60 00 80 00 4c 00 39 00 54 00 5b 00 4c 00 5b 00 3f 00 74 00 58 00 38 00 3c } //1
		$a_01_2 = {58 00 7c 00 6c 00 71 00 58 00 6b 00 72 00 51 00 6e 00 50 00 74 00 57 00 4a 00 3c 00 49 00 3e 00 } //1 X|lqXkrQnPtWJ<I>
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}