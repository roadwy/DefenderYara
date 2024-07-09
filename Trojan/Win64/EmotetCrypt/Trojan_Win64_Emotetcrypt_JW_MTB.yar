
rule Trojan_Win64_Emotetcrypt_JW_MTB{
	meta:
		description = "Trojan:Win64/Emotetcrypt.JW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 63 c9 48 2b c1 48 63 0d ?? ?? ?? ?? 48 03 4c 24 48 0f b6 04 01 03 44 24 30 8b 4c 24 04 33 c8 8b c1 8b 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 8b 14 24 2b d1 8b ca 03 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 2b ca 03 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 2b ca } //1
		$a_01_1 = {73 55 31 76 61 62 59 40 33 3e 44 46 79 55 74 63 66 29 39 24 5e 2b 56 6c 36 69 72 62 44 3e 6f 6c 45 45 5e 3c 24 40 50 57 55 6a 73 52 30 4d 2b 4b 73 23 6a 6c 6d 72 58 67 25 54 45 } //1 sU1vabY@3>DFyUtcf)9$^+Vl6irbD>olEE^<$@PWUjsR0M+Ks#jlmrXg%TE
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}