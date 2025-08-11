
rule Trojan_BAT_Noswk_PGN_MTB{
	meta:
		description = "Trojan:BAT/Noswk.PGN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_80_0 = {59 55 68 53 4d 47 4e 49 54 54 5a 4d 65 54 6c 76 59 54 4e 57 4d 55 78 74 4f 58 70 6a 65 54 46 71 59 6d 6b 78 62 32 49 79 4e 57 35 68 4d 6a 6c 31 57 6e 6b 31 61 47 4a 48 62 44 56 6b 56 7a 56 71 59 33 6b 31 61 6d 49 79 4d 48 5a 53 62 57 77 30 54 44 42 61 63 47 56 44 4e 54 42 6c 53 46 45 39 } //YUhSMGNITTZMeTlvYTNWMUxtOXpjeTFqYmkxb2IyNW5hMjl1Wnk1aGJHbDVkVzVqY3k1amIyMHZSbWw0TDBacGVDNTBlSFE9  1
		$a_01_1 = {44 65 6f 62 66 75 73 63 61 74 65 53 74 72 69 6e 67 } //2 DeobfuscateString
		$a_01_2 = {44 65 63 6f 64 65 42 61 73 65 36 34 54 6f 55 72 6c } //2 DecodeBase64ToUrl
	condition:
		((#a_80_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=5
 
}