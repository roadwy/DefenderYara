
rule Trojan_Win64_Androm_CCHA_MTB{
	meta:
		description = "Trojan:Win64/Androm.CCHA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8d 05 8a 6a 02 00 48 89 85 d0 00 00 00 48 8d 05 85 6a 02 00 48 89 85 d8 00 00 00 48 8d 05 7e 6a 02 00 48 89 85 e0 00 00 00 48 8d 05 84 6a 02 00 48 89 85 e8 00 00 00 48 8d 05 80 6a 02 00 48 89 85 f0 00 00 00 48 8d 05 81 6a 02 00 48 89 85 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}