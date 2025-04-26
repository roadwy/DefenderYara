
rule Trojan_Win64_CobaltStrike_AWV_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.AWV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {41 b9 40 00 00 00 41 b8 00 10 00 00 48 8b d6 33 c9 ff 15 } //1
		$a_01_1 = {f3 0f 6f 41 f0 66 0f 6f ca 66 0f ef c8 f3 0f 7f 49 f0 f3 0f 6f 01 66 0f 6f ca 66 0f ef c8 f3 0f 7f 09 f3 0f 6f 41 10 66 0f ef c2 f3 0f 7f 41 10 83 c2 40 48 8d 49 40 49 8d 04 08 49 3b c1 7c b2 } //1
		$a_01_2 = {4c 6f 63 6b 44 6f 77 6e 50 72 6f 74 65 63 74 50 72 6f 63 65 73 73 42 79 49 64 } //1 LockDownProtectProcessById
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}