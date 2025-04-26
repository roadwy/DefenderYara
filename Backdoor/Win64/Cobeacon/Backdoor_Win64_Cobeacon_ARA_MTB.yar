
rule Backdoor_Win64_Cobeacon_ARA_MTB{
	meta:
		description = "Backdoor:Win64/Cobeacon.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {80 32 77 48 8d 52 01 41 ff c0 48 8d 4c 24 ?? 48 [0-06] 48 ff c0 [0-04] 75 ?? 49 63 c8 48 3b c8 72 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}