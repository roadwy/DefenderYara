
rule Trojan_Win64_Tedy_ATT_MTB{
	meta:
		description = "Trojan:Win64/Tedy.ATT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {40 53 48 83 ec 20 48 8d 0d eb d6 16 00 ff 15 ?? ?? ?? ?? 48 8b c8 48 8d 15 53 a9 18 00 48 8b d8 ff 15 ?? ?? ?? ?? 48 8d 15 eb d6 16 00 48 8b cb } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}