
rule Trojan_Win32_Emotetcrypt_GK_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.GK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 0c 08 8b 45 0c 0f b6 14 10 33 d1 a1 90 01 04 0f af 05 90 01 04 0f af 05 90 01 04 8b 4d f4 03 0d 90 01 04 2b c8 8b 45 0c 88 14 08 90 00 } //1
		$a_81_1 = {48 4f 45 56 3e 5e 79 39 4a 36 78 76 59 70 4d 4f 6e 5a 76 76 40 63 6b 42 4d 65 55 76 4a 64 55 21 25 4b 56 50 4a 74 21 71 33 55 39 47 61 66 3f 56 54 5a 6c 59 70 6c 73 34 3c 4a 33 38 4f 66 66 73 79 48 73 47 4f 6c 4b 62 2b 4e 30 46 49 28 3f 41 } //1 HOEV>^y9J6xvYpMOnZvv@ckBMeUvJdU!%KVPJt!q3U9Gaf?VTZlYpls4<J38OffsyHsGOlKb+N0FI(?A
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}