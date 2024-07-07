
rule Trojan_Win64_Coinminer_SA{
	meta:
		description = "Trojan:Win64/Coinminer.SA,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 59 4a 5f 50 72 6f 6a 65 63 74 5c 4d 69 6e 69 6e 67 5f 63 70 70 5c 43 6f 6e 68 6f 73 74 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 63 6f 6e 68 6f 73 74 2e 70 64 62 } //1 C:\YJ_Project\Mining_cpp\Conhost\x64\Release\conhost.pdb
	condition:
		((#a_01_0  & 1)*1) >=1
 
}