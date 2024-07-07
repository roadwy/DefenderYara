
rule Trojan_Win64_Obsidium_AMBG_MTB{
	meta:
		description = "Trojan:Win64/Obsidium.AMBG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {4d 5a 25 e5 ce 2f 84 d6 04 63 a4 56 cc 46 72 a2 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}