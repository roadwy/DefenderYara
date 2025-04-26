
rule Backdoor_BAT_AsyncRAT_Y_MTB{
	meta:
		description = "Backdoor:BAT/AsyncRAT.Y!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {20 e8 03 00 00 28 ?? 00 00 06 20 ?? ?? ?? 13 2b ?? 06 17 58 0a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}