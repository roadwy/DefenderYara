
rule Trojan_BAT_Redline_IB_MTB{
	meta:
		description = "Trojan:BAT/Redline.IB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 4c 67 43 78 72 65 56 64 49 } //01 00  dLgCxreVdI
		$a_01_1 = {67 75 33 39 6a 73 59 42 74 70 44 45 47 44 64 70 61 43 4f } //01 00  gu39jsYBtpDEGDdpaCO
		$a_80_2 = {50 72 6f 66 69 6c 65 5f 65 6e 63 72 79 70 74 65 64 5f 76 61 6c 75 65 25 61 70 70 64 61 74 61 25 5c 6c 6f 67 69 6e 73 } //Profile_encrypted_value%appdata%\logins  01 00 
		$a_01_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_4 = {54 6f 41 72 72 61 79 } //00 00  ToArray
	condition:
		any of ($a_*)
 
}