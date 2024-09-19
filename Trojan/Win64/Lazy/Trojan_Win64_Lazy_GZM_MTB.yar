
rule Trojan_Win64_Lazy_GZM_MTB{
	meta:
		description = "Trojan:Win64/Lazy.GZM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {33 d2 c7 45 f0 38 02 00 00 8d 4a 02 ff 15 ?? ?? ?? ?? 48 8b c8 48 8d 55 f0 48 8b d8 ff 15 ?? ?? ?? ?? 83 f8 01 ?? ?? 48 8d 55 f0 48 8b cb ff 15 ?? ?? ?? ?? 83 f8 01 75 } //5
		$a_01_1 = {9b 4e 4b 73 66 cf 4e 72 9b 4e 4a 73 e7 cf 4e 72 9b 4e 4d 73 ed cf 4e 72 eb cf 4e 72 e9 cf 4e 72 ed 4e 4b 73 c3 cf 4e 72 ed 4e 4a 73 fb cf 4e 72 } //1
		$a_01_2 = {43 56 45 2d 32 30 32 34 2d 33 30 30 38 38 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 70 6f 63 2e 70 64 62 00 } //1
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}