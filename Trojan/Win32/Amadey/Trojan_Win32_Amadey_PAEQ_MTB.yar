
rule Trojan_Win32_Amadey_PAEQ_MTB{
	meta:
		description = "Trojan:Win32/Amadey.PAEQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 03 8b 1c 24 83 c4 04 51 b9 00 00 00 00 01 f1 52 51 b9 00 00 00 00 89 ca 59 01 ca 01 1a 5a 59 53 bb 04 00 00 00 57 bf ee 84 bf 5e 01 fe 5f 01 de 81 ee ee 84 bf 5e 5b } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}