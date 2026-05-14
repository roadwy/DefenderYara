
rule Trojan_Win64_Mikey_KKA_MTB{
	meta:
		description = "Trojan:Win64/Mikey.KKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 66 83 f9 01 66 0f 45 c1 0f b7 c8 0f ?? ?? ?? ?? 30 02 66 ff c1 48 8d 52 01 49 83 e8 01 } //20
	condition:
		((#a_03_0  & 1)*20) >=20
 
}