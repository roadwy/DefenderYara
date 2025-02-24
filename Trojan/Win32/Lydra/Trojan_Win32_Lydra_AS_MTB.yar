
rule Trojan_Win32_Lydra_AS_MTB{
	meta:
		description = "Trojan:Win32/Lydra.AS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 fc 8a 44 30 ff 8b d0 c1 e2 06 25 ff 00 00 00 c1 e8 02 0a c2 33 db 8a d8 8b c6 25 ff 00 00 00 33 d8 83 eb 0c 85 db 7d 06 81 c3 00 01 00 00 81 f3 c2 00 00 00 81 eb f6 00 00 00 85 db 7d 06 81 c3 00 01 00 00 83 f3 62 8d 45 f4 8b d3 e8 ?? ?? ?? ?? 8b 55 f4 8b 45 f8 e8 ?? ?? ?? ?? 8b 45 f8 46 4f 75 } //4
		$a_01_1 = {37 38 6c 39 41 6e 42 49 43 47 4b 4c 57 34 63 4e 4f 5a 6d 33 6a 50 51 52 55 56 58 4a 59 67 62 64 46 4d } //1 78l9AnBICGKLW4cNOZm3jPQRUVXJYgbdFM
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}