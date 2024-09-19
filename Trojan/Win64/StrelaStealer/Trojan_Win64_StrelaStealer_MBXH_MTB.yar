
rule Trojan_Win64_StrelaStealer_MBXH_MTB{
	meta:
		description = "Trojan:Win64/StrelaStealer.MBXH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {38 30 00 00 01 00 00 00 01 00 00 00 01 00 00 00 45 30 00 00 49 30 00 00 4d 30 00 00 50 72 6f 6a 65 63 74 31 2e 64 6c 6c [0-20] 65 6e 74 72 79 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}