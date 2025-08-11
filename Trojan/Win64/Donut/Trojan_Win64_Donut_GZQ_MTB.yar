
rule Trojan_Win64_Donut_GZQ_MTB{
	meta:
		description = "Trojan:Win64/Donut.GZQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 fc 48 63 d0 48 8b 45 10 48 01 d0 0f b6 00 32 45 20 89 c1 8b 45 fc 48 63 d0 48 8b 45 28 48 01 d0 89 ca 88 10 83 45 fc 01 8b 45 fc 3b 45 18 7c } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}