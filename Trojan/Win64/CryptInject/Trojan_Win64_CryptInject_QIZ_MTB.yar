
rule Trojan_Win64_CryptInject_QIZ_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.QIZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {c5 c1 fc da c4 42 31 dc cf c5 fd fe c4 c5 e5 72 f4 07 c4 41 3d fe c4 c5 dd ef e3 c4 43 1d 0f e4 ?? c4 41 3d fe c4 c5 fd fe c4 c4 41 3d fe c4 c4 e3 5d 46 d8 02 c4 e3 5d 46 e0 13 c4 c3 1d 46 c0 02 c4 43 1d 46 c0 13 c4 e3 45 46 c3 02 44 30 14 0f c4 43 1d 46 c0 13 48 ff c1 c4 e3 45 46 c3 ?? 48 89 c8 c4 41 3d fe c4 48 81 f9 d3 13 1c 00 0f 86 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}