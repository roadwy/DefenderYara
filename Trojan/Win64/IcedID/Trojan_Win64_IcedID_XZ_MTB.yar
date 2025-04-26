
rule Trojan_Win64_IcedID_XZ_MTB{
	meta:
		description = "Trojan:Win64/IcedID.XZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_01_0 = {48 f7 e1 48 8b c1 ff c3 48 2b c2 48 d1 e8 48 03 c2 48 c1 e8 04 48 6b c0 1c 48 2b c8 8a 4c 0d e0 43 32 0c 02 41 88 08 49 ff c0 } //5
		$a_01_1 = {65 48 8b 0c 25 60 00 00 00 8b 91 bc 00 00 00 c1 ea 08 f6 c2 01 75 04 } //5
		$a_01_2 = {62 68 75 66 } //1 bhuf
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1) >=11
 
}