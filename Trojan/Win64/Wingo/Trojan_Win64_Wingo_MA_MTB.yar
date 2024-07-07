
rule Trojan_Win64_Wingo_MA_MTB{
	meta:
		description = "Trojan:Win64/Wingo.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 83 ec 60 48 89 6c 24 58 48 8d 6c 24 58 83 3d 90 01 04 02 90 01 01 0f 84 90 01 04 48 85 c0 0f 84 90 01 04 88 4c 24 78 48 89 5c 24 70 80 3d 65 f4 20 00 00 90 01 01 0f 84 80 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}