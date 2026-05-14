
rule Trojan_Win32_Copak_KK_MTB{
	meta:
		description = "Trojan:Win32/Copak.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 01 00 00 "
		
	strings :
		$a_03_0 = {7c 9a 65 00 [0-0f] 8d [0-32] 81 ?? ff 00 00 00 [0-1e] 81 ?? f4 01 00 00 75 } //20
	condition:
		((#a_03_0  & 1)*20) >=20
 
}