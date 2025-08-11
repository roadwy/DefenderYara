
rule Backdoor_Win64_AKHttpClient_A{
	meta:
		description = "Backdoor:Win64/AKHttpClient.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {56 48 42 44 40 48 ?? ?? ?? ?? ?? ?? 75 6e 6b 6e 6f 77 6e 2e 6c 6f 63 61 6c 00 00 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}