
rule Trojan_Win64_InfoStealer_PAA_MTB{
	meta:
		description = "Trojan:Win64/InfoStealer.PAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {49 83 f9 04 74 2b 45 31 d2 49 83 fa 40 74 11 46 8a 1c 12 47 32 1c 10 46 88 1c 11 49 ff c2 eb e9 49 ff c1 49 83 c0 40 48 83 c2 40 48 83 c1 40 eb cf } //2
		$a_01_1 = {74 10 8a 8c 04 b0 00 00 00 41 30 0c 04 48 ff c0 eb eb } //3
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*3) >=5
 
}