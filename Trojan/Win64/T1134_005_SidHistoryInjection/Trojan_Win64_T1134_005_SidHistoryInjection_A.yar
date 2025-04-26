
rule Trojan_Win64_T1134_005_SidHistoryInjection_A{
	meta:
		description = "Trojan:Win64/T1134_005_SidHistoryInjection.A,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {73 00 69 00 64 00 3a 00 3a 00 61 00 64 00 64 00 } //10 sid::add
		$a_01_1 = {6b 00 65 00 72 00 62 00 65 00 72 00 6f 00 73 00 3a 00 3a 00 67 00 6f 00 6c 00 64 00 65 00 6e 00 } //10 kerberos::golden
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=10
 
}