
rule Trojan_Win64_RedParrot_A_dha{
	meta:
		description = "Trojan:Win64/RedParrot.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {53 00 70 00 6c 00 75 00 6e 00 6b 00 39 00 34 00 31 00 49 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 5f 00 } //1 Splunk941Install_
		$a_03_1 = {32 00 30 00 32 00 35 00 30 00 35 00 30 00 37 00 2d 00 32 00 33 00 30 00 30 00 30 00 ?? ?? 2e 00 6c 00 6f 00 67 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}