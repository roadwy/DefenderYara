
rule Trojan_Win64_AsyncRat_BT_MTB{
	meta:
		description = "Trojan:Win64/AsyncRat.BT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {4c 01 c2 48 81 c2 ?? 00 00 00 44 33 12 41 01 c2 48 81 c1 01 00 00 00 48 81 f9 ?? ?? 00 00 44 89 d0 44 89 55 ?? 48 89 4d ?? 89 45 ?? 75 } //4
		$a_03_1 = {4d 01 c1 49 81 c1 ?? 00 00 00 45 8b 11 } //1
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*1) >=5
 
}