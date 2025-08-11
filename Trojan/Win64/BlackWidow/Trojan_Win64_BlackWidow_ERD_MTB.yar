
rule Trojan_Win64_BlackWidow_ERD_MTB{
	meta:
		description = "Trojan:Win64/BlackWidow.ERD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 8b d0 c1 ea 18 88 14 01 41 8b d0 ff 05 87 0b 01 00 8b 05 c1 0b 01 00 01 83 58 01 00 00 48 8b 05 cc 0b 01 00 48 63 8b ?? ?? ?? ?? c1 ea 10 88 14 01 41 8b d0 ff 83 ?? ?? ?? ?? 48 8b 0d b7 0a 01 00 c1 ea 08 8b 81 1c 01 00 00 33 05 28 0c 01 00 35 8a 56 0f 00 89 81 1c 01 00 00 48 63 0d 36 0b 01 00 48 8b 83 e8 00 00 00 88 14 01 ff 05 26 0b 01 00 48 63 8b ?? ?? ?? ?? 48 8b 83 e8 00 00 00 44 88 04 01 ff 83 ?? ?? ?? ?? 49 81 f9 c0 5d 00 00 0f 8c } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}