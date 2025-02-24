
rule Trojan_Win64_Cryptinject_YBA_MTB{
	meta:
		description = "Trojan:Win64/Cryptinject.YBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 45 df 21 c2 8a 55 ec 48 03 5d e8 03 5d c4 48 8b 45 ac 0f b7 d2 } //11
	condition:
		((#a_01_0  & 1)*11) >=11
 
}