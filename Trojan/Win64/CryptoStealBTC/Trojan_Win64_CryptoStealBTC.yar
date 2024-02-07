
rule Trojan_Win64_CryptoStealBTC{
	meta:
		description = "Trojan:Win64/CryptoStealBTC,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_00_0 = {31 00 37 00 63 00 39 00 59 00 37 00 53 00 67 00 58 00 39 00 74 00 68 00 64 00 61 00 77 00 79 00 55 00 79 00 48 00 59 00 79 00 45 00 42 00 65 00 41 00 37 00 45 00 7a 00 34 00 32 00 72 00 4e 00 57 00 67 00 } //00 00  17c9Y7SgX9thdawyUyHYyEBeA7Ez42rNWg
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_CryptoStealBTC_2{
	meta:
		description = "Trojan:Win64/CryptoStealBTC,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_00_0 = {62 00 63 00 31 00 71 00 79 00 65 00 6d 00 76 00 36 00 75 00 66 00 7a 00 74 00 65 00 32 00 7a 00 72 00 76 00 64 00 7a 00 35 00 65 00 77 00 65 00 73 00 6d 00 68 00 70 00 71 00 7a 00 6a 00 78 00 7a 00 74 00 7a 00 61 00 35 00 6d 00 70 00 34 00 6b 00 71 00 } //00 00  bc1qyemv6ufzte2zrvdz5ewesmhpqzjxztza5mp4kq
	condition:
		any of ($a_*)
 
}