
rule Trojan_Win64_GoRat_MV_MSR{
	meta:
		description = "Trojan:Win64/GoRat.MV!MSR,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {61 6c 6c 6f 63 41 6c 6c 00 30 30 4f 4f 30 30 4f 4f 4f 4f 4f 4f 30 4f 30 4f 4f 00 30 4f 30 30 30 30 30 6f 4f 30 30 30 6f 4f 4f 30 4f 30 4f 6f 00 6f 30 4f 4f 6f 30 30 6f 4f 4f 4f 30 30 30 30 30 4f 30 4f 6f 00 30 4f 30 30 30 6f 30 6f 6f 30 4f 4f 6f 4f 6f 4f 30 00 72 75 6e 74 69 6d 65 2e 28 2a 62 75 63 6b 65 74 29 2e 73 74 6b } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}