
rule Trojan_Win64_Zusy_GTN_MTB{
	meta:
		description = "Trojan:Win64/Zusy.GTN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {40 34 52 2a cd fe 40 d4 b6 5e 32 01 bf ?? ?? ?? ?? 40 22 38 0c 32 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}