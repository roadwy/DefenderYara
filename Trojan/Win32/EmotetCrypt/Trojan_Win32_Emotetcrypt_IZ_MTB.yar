
rule Trojan_Win32_Emotetcrypt_IZ_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.IZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f af d6 0f af 15 ?? ?? ?? ?? 8b 2d ?? ?? ?? ?? 03 e9 8d 4c 6a 02 0f af 0d ?? ?? ?? ?? 2b d9 48 0f af c6 03 fb 8b 4c 24 48 8a 14 38 8b 44 24 28 8a 18 32 da 88 18 } //1
		$a_01_1 = {53 46 6e 46 78 6f 4d 41 38 65 32 52 26 5f 5e 6e 72 45 41 57 73 56 68 6c 78 51 53 39 50 26 44 2a 44 25 3e 65 59 6e 67 4e 64 73 47 78 34 40 65 30 48 45 43 23 62 39 59 76 45 24 29 31 67 6d 6b 58 68 5e 42 4e 75 30 } //1 SFnFxoMA8e2R&_^nrEAWsVhlxQS9P&D*D%>eYngNdsGx4@e0HEC#b9YvE$)1gmkXh^BNu0
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}