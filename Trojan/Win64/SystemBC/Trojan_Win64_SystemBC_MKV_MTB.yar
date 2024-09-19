
rule Trojan_Win64_SystemBC_MKV_MTB{
	meta:
		description = "Trojan:Win64/SystemBC.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {49 8b cf 8a 04 1f 30 03 48 ff c3 48 83 e9 01 75 f2 } //1
		$a_03_1 = {4c 8b c6 4c 2b c0 48 8d 4d ?? 48 03 ca 48 ff c2 41 8a 04 08 34 36 88 01 48 3b d3 72 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}