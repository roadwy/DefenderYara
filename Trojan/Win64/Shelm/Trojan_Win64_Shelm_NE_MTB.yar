
rule Trojan_Win64_Shelm_NE_MTB{
	meta:
		description = "Trojan:Win64/Shelm.NE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8d 4c 24 ?? 48 85 f6 74 3f 4c 8d 05 6b 30 fe ff 48 3b ca 73 33 80 39 ?? 75 14 48 8d 42 ?? 48 3b c8 73 1a 80 79 01 ?? 75 14 48 ff c1 eb 0f 0f b6 01 4a 0f be 84 00 ?? ?? ?? ?? 48 03 c8 48 ff c7 48 ff c1 48 3b fe } //3
		$a_01_1 = {54 61 72 67 65 74 20 66 75 6e 63 74 69 6f 6e 20 63 61 6c 6c 65 64 21 } //1 Target function called!
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}