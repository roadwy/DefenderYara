
rule Trojan_Win64_T1558_003_Kerberoasting_A{
	meta:
		description = "Trojan:Win64/T1558_003_Kerberoasting.A,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {6b 00 65 00 72 00 62 00 65 00 72 00 6f 00 73 00 3a 00 3a 00 61 00 73 00 6b 00 } //10 kerberos::ask
	condition:
		((#a_01_0  & 1)*10) >=10
 
}