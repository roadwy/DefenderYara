
rule Backdoor_Win64_AKDnsClient_A{
	meta:
		description = "Backdoor:Win64/AKDnsClient.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 65 73 75 6c 74 5f 72 65 63 65 69 76 65 64 ?? 56 48 42 44 40 48 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}