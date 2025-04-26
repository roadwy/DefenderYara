
rule Trojan_Win64_Latrodectus_GND_MTB{
	meta:
		description = "Trojan:Win64/Latrodectus.GND!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {4d 31 ca 49 c1 e1 ?? 41 88 0c 08 c5 e5 d4 d9 48 ff c1 49 c1 e9 ?? 48 83 f9 ?? ?? ?? ?? 49 83 c9 ?? 48 31 c9 ?? 48 ff c2 48 81 fa } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}