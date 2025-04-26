
rule Trojan_Win64_Redcape_RPY_MTB{
	meta:
		description = "Trojan:Win64/Redcape.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 5e 0f 73 d4 0e 0f de e5 41 5d 80 34 01 75 53 90 0f 77 41 50 0f ea c8 41 58 48 ff c3 66 83 eb 02 5b 48 ff c0 48 83 f8 04 75 a3 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}