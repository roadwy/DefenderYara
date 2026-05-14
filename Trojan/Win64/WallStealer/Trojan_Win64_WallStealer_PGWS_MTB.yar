
rule Trojan_Win64_WallStealer_PGWS_MTB{
	meta:
		description = "Trojan:Win64/WallStealer.PGWS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b cb 0f 57 c8 f3 41 0f 6f 04 3b f3 41 0f 7f 0c 30 45 8d 43 10 f3 0f 6f 4c 0c 60 43 8d 0c 1f 0f 57 c8 f3 41 0f 6f 04 38 f3 41 0f 7f 0c 33 41 83 c3 40 f3 0f 6f 4c 0c 60 0f 57 c8 f3 41 0f 7f 0c 30 3b c5 72 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}