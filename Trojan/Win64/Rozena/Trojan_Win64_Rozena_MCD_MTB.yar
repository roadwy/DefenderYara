
rule Trojan_Win64_Rozena_MCD_MTB{
	meta:
		description = "Trojan:Win64/Rozena.MCD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8b 0e 48 8b d7 41 ff d6 85 c0 0f 85 ?? ?? 00 00 48 83 c7 ?? ff c3 48 83 c6 ?? 83 fb ?? 72 } //2
		$a_01_1 = {44 65 6f 62 66 75 73 63 61 74 65 64 20 50 61 79 6c 6f 61 64 } //2 Deobfuscated Payload
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}