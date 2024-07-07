
rule Trojan_Linux_BashMiner_A{
	meta:
		description = "Trojan:Linux/BashMiner.A,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {24 7b 6a 6e 64 69 3a 6c 64 61 70 3a 2f 2f 90 02 0f 2f 62 61 73 69 63 2f 63 6f 6d 6d 61 6e 64 2f 62 61 73 65 36 34 2f } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}