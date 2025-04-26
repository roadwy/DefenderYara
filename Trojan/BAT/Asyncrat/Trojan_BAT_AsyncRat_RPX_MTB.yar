
rule Trojan_BAT_AsyncRat_RPX_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 8e 69 5d 18 58 1b 58 1d 59 03 08 03 8e 69 5d 91 07 08 07 8e 69 5d 18 58 1b 58 1d 59 91 61 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_AsyncRat_RPX_MTB_2{
	meta:
		description = "Trojan:BAT/AsyncRat.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {fe 0c 07 00 59 3b 40 01 00 00 fe 0c 02 00 1f fe fe 0e 08 00 fe 0c 08 00 65 3b e7 00 00 00 fe 0c 02 00 1f fc fe 0e 09 00 16 fe 0e 0a 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_AsyncRat_RPX_MTB_3{
	meta:
		description = "Trojan:BAT/AsyncRat.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0c 00 00 "
		
	strings :
		$a_01_0 = {41 73 79 6e 63 43 6c 69 65 6e 74 } //1 AsyncClient
		$a_01_1 = {50 61 73 74 65 62 69 6e } //1 Pastebin
		$a_01_2 = {4b 65 65 70 41 6c 69 76 65 50 61 63 6b 65 74 } //1 KeepAlivePacket
		$a_01_3 = {47 65 74 54 65 6d 70 50 61 74 68 } //1 GetTempPath
		$a_01_4 = {41 6e 74 69 76 69 72 75 73 } //1 Antivirus
		$a_01_5 = {43 72 65 61 74 65 4d 75 74 65 78 } //1 CreateMutex
		$a_01_6 = {47 65 74 46 6f 72 65 67 72 6f 75 6e 64 57 69 6e 64 6f 77 } //1 GetForegroundWindow
		$a_01_7 = {53 74 72 52 65 76 65 72 73 65 } //1 StrReverse
		$a_01_8 = {67 65 74 5f 4f 53 46 75 6c 6c 4e 61 6d 65 } //1 get_OSFullName
		$a_01_9 = {73 65 74 5f 55 73 65 53 68 65 6c 6c 45 78 65 63 75 74 65 } //1 set_UseShellExecute
		$a_01_10 = {41 63 74 69 76 61 74 65 50 6f 6e 67 } //1 ActivatePong
		$a_01_11 = {41 73 79 6e 63 52 65 73 75 6c 74 } //1 AsyncResult
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1) >=12
 
}