
rule Trojan_Win32_Emotetcrypt_HD_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.HD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 d2 2b ea 8b 15 90 01 04 03 ea 8d 2c a8 8b 44 24 20 83 c0 01 0f af c2 03 c6 0f af 05 90 01 04 03 c6 0f af f7 03 c7 03 c1 8d 0c b5 90 01 04 0f af cb 83 c1 04 0f af cb 8d 04 40 2b e8 03 6c 24 2c 8b 44 24 24 0f b6 14 29 30 10 90 00 } //1
		$a_81_1 = {79 65 72 59 58 57 38 26 4d 78 4f 28 69 21 4b 76 6b 3e 28 5f 69 67 29 21 68 4d 37 32 63 24 48 77 66 64 2b 49 45 37 2a } //1 yerYXW8&MxO(i!Kvk>(_ig)!hM72c$Hwfd+IE7*
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}