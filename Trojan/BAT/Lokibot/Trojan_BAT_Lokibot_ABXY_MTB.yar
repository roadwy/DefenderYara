
rule Trojan_BAT_Lokibot_ABXY_MTB{
	meta:
		description = "Trojan:BAT/Lokibot.ABXY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 07 00 00 06 00 "
		
	strings :
		$a_81_0 = {69 59 35 66 79 45 36 66 73 55 33 48 69 } //06 00  iY5fyE6fsU3Hi
		$a_81_1 = {56 59 61 5f 63 42 66 6b 68 2f 70 75 72 } //01 00  VYa_cBfkh/pur
		$a_00_2 = {24 35 33 64 30 34 65 61 30 2d 30 62 61 61 2d 34 62 36 33 2d 62 31 61 30 2d 61 62 33 32 64 33 38 39 36 37 61 32 } //01 00  $53d04ea0-0baa-4b63-b1a0-ab32d38967a2
		$a_81_3 = {47 65 74 48 61 73 68 43 6f 64 65 } //01 00  GetHashCode
		$a_81_4 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_81_5 = {53 75 73 70 65 6e 64 4c 61 79 6f 75 74 } //01 00  SuspendLayout
		$a_81_6 = {53 74 72 65 61 6d 52 65 61 64 65 72 } //00 00  StreamReader
	condition:
		any of ($a_*)
 
}