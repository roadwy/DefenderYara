
rule Trojan_Win64_Stealc_DN_MTB{
	meta:
		description = "Trojan:Win64/Stealc.DN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b 55 d8 48 8b 45 f0 48 01 d0 0f b6 10 48 8b 4d d8 48 8b 45 f0 48 01 c8 83 f2 29 88 10 50 51 59 58 48 83 45 f0 01 48 8b 45 f0 48 3b 45 d0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}