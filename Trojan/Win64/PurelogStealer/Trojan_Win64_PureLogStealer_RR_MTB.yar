
rule Trojan_Win64_PureLogStealer_RR_MTB{
	meta:
		description = "Trojan:Win64/PureLogStealer.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {61 7e 21 04 00 04 7b 1e 04 00 04 61 7e } //1
		$a_01_1 = {4d 75 74 65 78 } //1 Mutex
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}