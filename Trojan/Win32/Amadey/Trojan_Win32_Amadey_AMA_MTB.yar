
rule Trojan_Win32_Amadey_AMA_MTB{
	meta:
		description = "Trojan:Win32/Amadey.AMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 c5 81 c0 4c 00 00 00 b9 c2 05 00 00 ba 83 be 29 a5 30 10 40 49 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}