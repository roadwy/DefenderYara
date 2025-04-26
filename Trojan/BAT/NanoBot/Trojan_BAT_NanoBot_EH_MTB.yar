
rule Trojan_BAT_NanoBot_EH_MTB{
	meta:
		description = "Trojan:BAT/NanoBot.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {52 53 41 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //1 RSACryptoServiceProvider
		$a_01_1 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } //1 RijndaelManaged
		$a_01_2 = {31 00 48 00 6f 00 55 00 77 00 6c 00 78 00 4b 00 39 00 47 00 67 00 59 00 34 00 51 00 6b 00 77 00 6c 00 32 00 2e 00 67 00 37 00 55 00 6f 00 4c 00 4e 00 49 00 34 00 72 00 5a 00 43 00 43 00 6a 00 77 00 5a 00 6b 00 49 00 6d 00 } //1 1HoUwlxK9GgY4Qkwl2.g7UoLNI4rZCCjwZkIm
		$a_01_3 = {64 00 38 00 6b 00 37 00 43 00 50 00 48 00 33 00 4a 00 57 00 73 00 76 00 46 00 71 00 55 00 61 00 33 00 4c 00 2e 00 57 00 4d 00 58 00 6e 00 57 00 76 00 55 00 44 00 5a 00 78 00 4e 00 52 00 52 00 75 00 55 00 59 00 76 00 33 00 } //1 d8k7CPH3JWsvFqUa3L.WMXnWvUDZxNRRuUYv3
		$a_01_4 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}