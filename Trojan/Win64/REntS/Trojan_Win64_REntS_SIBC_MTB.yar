
rule Trojan_Win64_REntS_SIBC_MTB{
	meta:
		description = "Trojan:Win64/REntS.SIBC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_00_0 = {4c 65 61 6b 65 64 20 48 65 61 70 20 41 64 64 72 65 73 73 } //10 Leaked Heap Address
		$a_03_1 = {44 8b da 48 85 c0 75 ?? b8 ?? ?? ?? ?? eb ?? 4c 8b d0 48 8b 81 ?? ?? ?? ?? 48 d1 e8 4d 8d 42 ?? 4c 03 c0 4c 89 41 ?? 8b 41 ?? 85 c0 7f ?? 45 85 db 74 ?? ff c8 33 d2 89 41 ?? 41 8b c3 f7 f3 80 c2 ?? 44 8b d8 80 fa ?? 7e ?? 41 8a c1 34 ?? c0 e0 ?? 04 ?? 02 d0 48 8b 41 ?? 88 10 48 ff 49 ?? eb } //1
	condition:
		((#a_00_0  & 1)*10+(#a_03_1  & 1)*1) >=11
 
}