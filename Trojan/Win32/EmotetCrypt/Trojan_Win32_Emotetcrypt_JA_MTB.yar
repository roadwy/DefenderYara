
rule Trojan_Win32_Emotetcrypt_JA_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.JA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 2c 83 c0 02 0f af c7 6b c0 03 03 d0 8d 41 03 0f af 05 ?? ?? ?? ?? 03 44 24 5c 2b d6 8b 74 24 44 0f af f1 03 c2 8a 0c 06 8b 44 24 48 30 08 } //1
		$a_01_1 = {6f 77 4e 3e 25 40 2b 45 4a 58 52 34 24 50 78 23 50 7a 4a 58 79 7a 51 5a 4b 32 46 5e 2a 71 6a 2a 4b 78 47 6b 21 5e 4d 31 70 58 4e 48 4e 71 } //1 owN>%@+EJXR4$Px#PzJXyzQZK2F^*qj*KxGk!^M1pXNHNq
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}