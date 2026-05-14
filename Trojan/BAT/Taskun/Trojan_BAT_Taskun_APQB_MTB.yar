
rule Trojan_BAT_Taskun_APQB_MTB{
	meta:
		description = "Trojan:BAT/Taskun.APQB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 5b 03 02 7b ?? 00 00 04 6f ?? 00 00 0a 5d 02 7b ?? 00 00 04 03 02 7b ?? 00 00 04 6f ?? 00 00 0a 5b 03 02 7b ?? 00 00 04 6f ?? 00 00 0a 5d 6f ?? ?? 00 0a 73 ?? ?? 00 0a 2a } //5
		$a_03_1 = {25 16 03 6f ?? ?? 00 0a 16 03 6f ?? ?? 00 0a 0a 12 00 28 ?? 00 00 0a 73 ?? ?? 00 0a a2 25 17 03 6f ?? ?? 00 0a 17 03 6f ?? ?? 00 0a 0a 12 00 28 ?? 00 00 0a 73 ?? ?? 00 0a a2 25 18 03 6f ?? ?? 00 0a 18 03 6f ?? ?? 00 0a 0a 12 00 28 ?? 00 00 0a 73 ?? ?? 00 0a a2 2a } //2
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*2) >=7
 
}