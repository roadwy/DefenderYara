
rule Trojan_Win64_Vidar_PL_MTB{
	meta:
		description = "Trojan:Win64/Vidar.PL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {4c 8d 05 b5 f6 0b 00 ba 01 00 00 00 57 56 53 48 83 ec 68 ff 15 e3 37 0c 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}