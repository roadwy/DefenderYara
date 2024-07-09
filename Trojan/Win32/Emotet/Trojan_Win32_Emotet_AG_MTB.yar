
rule Trojan_Win32_Emotet_AG_MTB{
	meta:
		description = "Trojan:Win32/Emotet.AG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 c8 8b 44 24 ?? 03 ce 03 da 8d 0c 49 03 c9 2b d9 8d 14 fd ?? ?? ?? ?? 2b da 0f b6 0c 2b 30 08 8b 44 24 ?? 40 89 44 24 ?? 3b 44 24 ?? 0f 82 } //1
		$a_01_1 = {4f 30 33 2a 58 34 72 4d 46 4a 31 57 6b 7a 52 59 66 54 38 6b 3e 33 35 79 4f 29 21 3e 79 25 30 52 74 6d 77 6f 40 66 74 6d 64 35 63 6f 78 59 23 26 69 64 31 75 4b 62 25 79 30 40 3c } //1 O03*X4rMFJ1WkzRYfT8k>35yO)!>y%0Rtmwo@ftmd5coxY#&id1uKb%y0@<
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}