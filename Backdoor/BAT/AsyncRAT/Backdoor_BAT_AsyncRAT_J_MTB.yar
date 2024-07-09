
rule Backdoor_BAT_AsyncRAT_J_MTB{
	meta:
		description = "Backdoor:BAT/AsyncRAT.J!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {00 00 01 0b 06 07 16 1a 6f ?? 00 00 0a 26 07 16 28 ?? 00 00 0a 0c 06 16 73 ?? 00 00 0a 0d } //1
		$a_03_1 = {07 20 00 01 00 00 6f ?? 00 00 0a 00 07 20 80 00 00 00 6f ?? 00 00 0a 00 07 17 6f ?? 00 00 0a 00 07 18 6f ?? 00 00 0a 00 07 02 7b ?? 00 00 04 6f ?? 00 00 0a 00 02 7b ?? 00 00 04 73 ?? 00 00 0a 0d } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}