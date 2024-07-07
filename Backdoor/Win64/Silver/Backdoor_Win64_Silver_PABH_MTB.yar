
rule Backdoor_Win64_Silver_PABH_MTB{
	meta:
		description = "Backdoor:Win64/Silver.PABH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {45 33 c9 4c 8b c1 49 83 ca ff 49 8b c2 48 ff c0 44 38 0c 01 75 f7 48 85 c0 74 1e 80 31 e6 41 ff c1 48 ff c1 49 8b d2 48 ff c2 41 80 3c 10 00 75 f6 49 63 c1 48 3b c2 72 e2 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}