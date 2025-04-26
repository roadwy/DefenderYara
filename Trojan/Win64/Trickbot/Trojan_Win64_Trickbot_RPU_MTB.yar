
rule Trojan_Win64_Trickbot_RPU_MTB{
	meta:
		description = "Trojan:Win64/Trickbot.RPU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {44 30 02 48 8d 52 01 ff c1 83 f9 1e 72 f2 45 33 c9 4c 89 6c 24 30 44 89 6c 24 28 48 8d 4c 24 40 ba 00 00 00 80 c7 44 24 20 03 00 00 00 45 8d 41 01 ff 15 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}