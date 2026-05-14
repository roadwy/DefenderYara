
rule Trojan_Win32_Copak_KKB_MTB{
	meta:
		description = "Trojan:Win32/Copak.KKB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 01 00 00 "
		
	strings :
		$a_03_0 = {a0 96 45 00 c3 [0-1f] cc ?? 47 00 [0-1f] e8 ?? 00 00 00 [0-1f] 31 [0-23] 81 ?? 02 00 00 00 [0-23] 39 ?? 7c } //20
	condition:
		((#a_03_0  & 1)*20) >=20
 
}