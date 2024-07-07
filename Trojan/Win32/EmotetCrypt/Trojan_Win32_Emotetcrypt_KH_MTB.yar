
rule Trojan_Win32_Emotetcrypt_KH_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.KH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b d0 2b 15 90 01 04 a1 90 01 04 0f af 05 90 01 04 03 d0 a1 90 01 04 0f af 05 90 01 04 2b d0 a1 90 01 04 0f af 05 90 01 04 03 15 90 01 04 03 c2 8b 15 90 01 04 0f af 15 90 01 04 03 55 14 0f b6 04 02 33 c8 8b 55 fc 2b 15 90 01 04 2b 15 90 01 04 2b 15 90 01 04 03 15 90 00 } //1
		$a_01_1 = {44 6f 4b 55 37 38 26 35 5e 4d 51 26 77 61 61 71 24 38 30 30 72 52 41 64 70 32 61 3f 24 5a 39 79 56 5a 57 34 4c 45 44 6e 73 38 4a 6f 71 70 54 6a 28 24 48 26 58 28 2a 55 6d 50 4f 61 49 56 41 52 70 21 71 39 32 66 32 70 34 29 } //1 DoKU78&5^MQ&waaq$800rRAdp2a?$Z9yVZW4LEDns8JoqpTj($H&X(*UmPOaIVARp!q92f2p4)
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}