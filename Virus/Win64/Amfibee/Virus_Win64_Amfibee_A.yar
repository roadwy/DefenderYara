
rule Virus_Win64_Amfibee_A{
	meta:
		description = "Virus:Win64/Amfibee.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {50 48 8d 0d 00 00 00 00 58 c3 5f e8 63 ff ff ff e8 eb ff ff ff 67 e3 0c 48 8b 73 10 48 ad 48 8b 68 20 eb 07 8b 73 08 ad 8b 68 18 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}