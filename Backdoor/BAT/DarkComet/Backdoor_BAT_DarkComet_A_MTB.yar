
rule Backdoor_BAT_DarkComet_A_MTB{
	meta:
		description = "Backdoor:BAT/DarkComet.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {70 17 15 16 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 72 ?? ?? ?? 70 72 ?? ?? ?? 70 17 15 16 28 ?? ?? ?? 0a 7e ?? ?? ?? 04 7e ?? ?? ?? 04 7e ?? ?? ?? 04 28 ?? ?? ?? 0a 26 06 2a } //1
		$a_03_1 = {0a 1a 9a 6f ?? ?? ?? 0a ?? 90 0a 1f 00 28 ?? ?? ?? 0a 7e ?? ?? ?? 04 7e ?? ?? ?? 04 15 16 28 } //1
		$a_03_2 = {0a 1a 9a 6f ?? ?? ?? 0a [0-02] 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 17 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 16 28 ?? ?? ?? 0a 16 33 90 0a 5c 00 6f ?? ?? ?? 0a 16 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 7e ?? ?? ?? 04 7e ?? ?? ?? 04 15 16 28 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}