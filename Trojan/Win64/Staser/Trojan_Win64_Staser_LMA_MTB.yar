
rule Trojan_Win64_Staser_LMA_MTB{
	meta:
		description = "Trojan:Win64/Staser.LMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {80 f2 41 41 88 10 4d 8d 40 01 41 0f b6 10 84 d2 } //20
		$a_01_1 = {80 f1 41 88 0a 48 8d 52 01 0f b6 0a 84 c9 } //10
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}