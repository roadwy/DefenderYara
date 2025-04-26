
rule Trojan_Win32_Remcos_RDF_MTB{
	meta:
		description = "Trojan:Win32/Remcos.RDF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {2b cb ba a0 93 16 00 8a 04 19 88 03 43 4a } //2
		$a_03_1 = {8b 95 24 ff ff ff 8b c1 83 e0 1f 8a 80 ?? ?? ?? ?? 30 04 0a 41 3b cf } //2
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}