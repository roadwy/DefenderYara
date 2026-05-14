
rule Trojan_Win32_Copak_KKA_MTB{
	meta:
		description = "Trojan:Win32/Copak.KKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 01 00 00 "
		
	strings :
		$a_03_0 = {a0 56 46 00 c3 [0-1a] 08 4a 48 00 [0-1a] e8 ?? 00 00 00 [0-1a] 31 [0-1a] 81 ?? 02 00 00 00 [0-1a] 39 ?? 7c } //20
	condition:
		((#a_03_0  & 1)*20) >=20
 
}