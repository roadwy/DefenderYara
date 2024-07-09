
rule Backdoor_BAT_Teweave_A{
	meta:
		description = "Backdoor:BAT/Teweave.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {1a 59 18 5b 1a 6f ?? ?? ?? ?? 16 0c 2b 2a 06 08 06 25 13 05 08 25 13 06 11 05 11 06 6f ?? ?? ?? ?? 07 d2 59 d2 25 13 07 6f ?? ?? ?? ?? 11 07 6f ?? ?? ?? ?? 08 17 58 } //5
		$a_03_1 = {1f 1d 12 00 1a 28 ?? 00 00 06 } //1
		$a_01_2 = {5b 00 53 00 59 00 4e 00 5d 00 } //1 [SYN]
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}