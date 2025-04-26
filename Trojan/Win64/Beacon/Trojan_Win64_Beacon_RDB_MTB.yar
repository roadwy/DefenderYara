
rule Trojan_Win64_Beacon_RDB_MTB{
	meta:
		description = "Trojan:Win64/Beacon.RDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 89 c1 83 e1 07 41 8a 0c 0a 41 30 0c 01 48 ff c0 eb e9 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}