
rule Trojan_Win64_IcedID_MKV_MTB{
	meta:
		description = "Trojan:Win64/IcedID.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {4d 63 c2 4d 8d 5b ?? 48 8b c7 41 ff c2 49 f7 e0 48 d1 ea 48 6b ca ?? 4c 2b c1 42 0f b6 44 84 ?? 41 30 43 ?? 41 81 fa ?? ?? ?? ?? 72 } //1
		$a_03_1 = {4d 63 c1 48 8d 49 ?? 48 8b c7 41 ff c1 49 f7 e0 48 d1 ea 48 6b c2 ?? 4c 2b c0 42 0f b6 44 84 ?? 30 41 ?? 41 81 f9 ?? ?? ?? ?? 72 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}