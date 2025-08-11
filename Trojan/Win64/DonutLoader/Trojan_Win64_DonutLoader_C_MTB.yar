
rule Trojan_Win64_DonutLoader_C_MTB{
	meta:
		description = "Trojan:Win64/DonutLoader.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {43 8b 14 91 39 c2 7e ?? 41 0f b6 14 00 41 8a 3c 03 48 ff c0 01 ca 48 63 d2 40 88 3c 16 eb } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}