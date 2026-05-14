
rule Trojan_Win64_Rhadamanthys_RRX_MTB{
	meta:
		description = "Trojan:Win64/Rhadamanthys.RRX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 0c 02 48 8b 55 f0 48 8b 45 f8 48 01 d0 44 89 c2 31 ca 88 10 48 83 45 f8 01 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}