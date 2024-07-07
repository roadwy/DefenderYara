
rule Trojan_Win64_IcedID_QD_MTB{
	meta:
		description = "Trojan:Win64/IcedID.QD!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4d 50 8b 45 48 03 c8 41 8b c7 f7 e9 8b c2 c1 e8 1f 03 d0 8d 04 52 3b c8 8b 45 48 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}