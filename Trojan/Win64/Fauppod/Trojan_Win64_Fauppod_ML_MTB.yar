
rule Trojan_Win64_Fauppod_ML_MTB{
	meta:
		description = "Trojan:Win64/Fauppod.ML!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b d0 48 2b d8 44 8b cf 0f 1f 00 41 0f b6 c8 32 0c 13 88 0a 41 80 c0 05 48 8d 52 01 49 83 e9 01 75 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}