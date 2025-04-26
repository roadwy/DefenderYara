
rule Ransom_Win64_LockCrypt_PB_MTB{
	meta:
		description = "Ransom:Win64/LockCrypt.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_03_0 = {33 c0 88 44 24 ?? 0f b6 44 24 ?? 0f 1f 40 00 0f be 44 14 ?? 8b 4c 24 ?? ?? ca 33 c8 88 4c 14 ?? 48 ff c2 48 83 fa 0d 72 } //3
		$a_03_1 = {33 c0 88 44 24 ?? 0f b6 44 24 ?? 48 8b c6 66 90 90 0f be 4c 04 ?? 8b 54 24 ?? ?? d0 33 d1 88 54 04 ?? 48 ff c0 48 83 f8 0d 72 } //3
		$a_01_2 = {2e 61 74 6f 6d 73 69 6c 6f } //1 .atomsilo
		$a_01_3 = {77 69 6e 73 74 61 30 5c 64 65 66 61 75 6c 74 } //1 winsta0\default
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=8
 
}