
rule Trojan_Win64_IcedID_NWT_MTB{
	meta:
		description = "Trojan:Win64/IcedID.NWT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {41 8a 04 00 88 04 0a e9 ?? ?? ?? ?? e9 ?? ?? ?? ?? 48 8b 4c 24 30 48 8d 44 01 18 eb ?? 41 81 c0 d5 00 00 00 8b d0 3a db 74 ?? 8b 44 24 20 8b 4c 24 20 3a d2 74 ?? 48 8b 54 24 28 4c 8b 84 24 c0 01 00 00 3a c0 74 } //1
		$a_01_1 = {71 73 4b 2e 64 6c 6c 00 42 5a 7a 6f 62 48 4f 67 4e 7a 6f 59 00 4a 62 61 64 73 6a 61 73 66 6b 73 00 5a 4c } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}