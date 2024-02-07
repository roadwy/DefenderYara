
rule Trojan_Win32_Farfli_BAQ_MTB{
	meta:
		description = "Trojan:Win32/Farfli.BAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 03 00 "
		
	strings :
		$a_01_0 = {8b 55 08 03 55 fc 0f be 02 2d ce 00 00 00 8b 4d 08 03 4d fc 88 01 8b 55 08 03 55 fc 0f be 02 35 c3 00 00 00 8b 4d 08 03 4d fc 88 01 eb } //01 00 
		$a_01_1 = {43 3a 5c 32 2e 74 78 74 } //01 00  C:\2.txt
		$a_01_2 = {5b 49 6e 73 65 72 74 5d } //01 00  [Insert]
		$a_01_3 = {5b 53 63 72 6f 6c 6c 20 4c 6f 63 6b 5d } //01 00  [Scroll Lock]
		$a_01_4 = {5b 50 72 69 6e 74 20 53 63 72 65 65 6e 5d } //00 00  [Print Screen]
	condition:
		any of ($a_*)
 
}