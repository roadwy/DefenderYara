
rule Trojan_Win64_Dridex_FD_MTB{
	meta:
		description = "Trojan:Win64/Dridex.FD!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b 4d 38 48 89 45 60 48 89 4d 00 48 8b 45 c0 48 89 45 60 48 8b 4d e8 8a 55 4b 88 11 8b 85 84 00 00 00 35 5e 52 00 00 8b 4d 2c 03 4d 2c 8b 55 5c 89 4d 2c 01 c2 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}