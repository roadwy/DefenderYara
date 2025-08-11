
rule Trojan_Win64_Zusy_UDP_MTB{
	meta:
		description = "Trojan:Win64/Zusy.UDP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 55 51 9c 49 bd 8b ca 09 38 80 26 3c e1 e8 28 f6 fd ff cf } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}