
rule Trojan_Win64_Farfli_SDM_MTB{
	meta:
		description = "Trojan:Win64/Farfli.SDM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {45 33 db 4c 8d 05 ?? ?? ?? ff 45 33 c9 4c 89 5c 24 28 33 d2 33 c9 44 89 5c 24 20 ff 15 ?? ?? ?? 00 83 ca ff 48 8b c8 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}