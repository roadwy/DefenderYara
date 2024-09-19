
rule Trojan_Win64_DBadur_AMAA_MTB{
	meta:
		description = "Trojan:Win64/DBadur.AMAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {80 c1 03 48 63 c2 42 30 4c 08 0a 41 ff 01 eb ?? 8d 41 05 44 3b c0 75 ?? 80 c1 04 48 63 c2 42 30 4c 08 0a 41 ff 01 eb 95 48 63 ca 8d 42 ?? 42 30 44 09 0a ff c2 83 fa 0e 72 } //3
		$a_80_1 = {68 74 74 70 73 3a 2f 2f 30 35 34 31 32 2e 6e 65 74 2f 7a 6d 6d } //https://05412.net/zmm  2
	condition:
		((#a_03_0  & 1)*3+(#a_80_1  & 1)*2) >=5
 
}