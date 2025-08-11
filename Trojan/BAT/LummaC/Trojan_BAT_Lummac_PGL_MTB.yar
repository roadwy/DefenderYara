
rule Trojan_BAT_Lummac_PGL_MTB{
	meta:
		description = "Trojan:BAT/Lummac.PGL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 05 11 07 1f 28 5a 58 13 08 28 ?? 00 00 0a 07 11 08 1e 6f ?? 00 00 0a 17 8d ?? 00 00 01 6f ?? 00 00 0a 13 09 11 09 28 ?? 00 00 0a 72 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
rule Trojan_BAT_Lummac_PGL_MTB_2{
	meta:
		description = "Trojan:BAT/Lummac.PGL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 2e 11 2b 11 2d 91 58 28 ?? 00 00 0a 72 f8 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 0a 5d 13 2e 20 ?? 00 00 00 fe 0e 33 00 38 9f fc ff ff 16 13 2e 38 0d 00 00 00 16 13 2d 20 ?? 00 00 00 38 8e fc ff ff } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_BAT_Lummac_PGL_MTB_3{
	meta:
		description = "Trojan:BAT/Lummac.PGL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 13 07 38 e3 ff ff ff 28 ?? 00 00 0a 11 01 11 08 1e 6f ?? 00 00 0a 17 8d ?? 00 00 01 6f ?? 00 00 0a 28 ?? 00 00 06 28 ?? 00 00 0a 72 02 01 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 0a 39 b0 ff ff ff 38 17 00 00 00 11 01 11 02 1c 58 28 ?? 00 00 0a 13 03 20 03 00 00 00 38 eb fd ff ff 11 01 11 08 1f 14 58 28 ?? 00 00 0a 13 09 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_BAT_Lummac_PGL_MTB_4{
	meta:
		description = "Trojan:BAT/Lummac.PGL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_80_0 = {59 54 56 6c 59 32 5a 6b 4e 32 52 6a 4f 44 51 7a 5a 54 4d 35 5a 54 41 34 5a 6d 45 34 4d 57 45 78 4d 7a 51 32 4e 54 46 6b 4e 6a 56 68 4e 6a 49 32 4d 44 45 77 4e 44 63 30 5a 54 4a 6d 4e 7a 51 33 59 7a 55 78 4d 44 67 33 4d 57 4a 6a 4d 54 63 31 4e 32 51 79 4d 67 3d 3d } //YTVlY2ZkN2RjODQzZTM5ZTA4ZmE4MWExMzQ2NTFkNjVhNjI2MDEwNDc0ZTJmNzQ3YzUxMDg3MWJjMTc1N2QyMg==  1
		$a_01_1 = {41 44 34 34 36 43 33 34 46 32 37 30 34 38 36 35 41 39 45 34 32 34 42 45 35 37 35 35 42 43 38 46 39 31 34 30 34 31 34 46 44 37 45 31 34 35 36 46 31 41 34 35 38 31 46 38 43 32 44 37 37 38 41 30 } //2 AD446C34F2704865A9E424BE5755BC8F9140414FD7E1456F1A4581F8C2D778A0
		$a_01_2 = {52 53 41 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //3 RSACryptoServiceProvider
		$a_00_3 = {43 72 65 61 74 65 45 6e 63 72 79 70 74 6f 72 } //4 CreateEncryptor
	condition:
		((#a_80_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*3+(#a_00_3  & 1)*4) >=10
 
}