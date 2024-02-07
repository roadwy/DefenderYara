
rule Trojan_BAT_SpySnake_MAC_MTB{
	meta:
		description = "Trojan:BAT/SpySnake.MAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {45 6e 71 75 65 75 65 } //01 00  Enqueue
		$a_01_1 = {44 65 71 75 65 75 65 } //01 00  Dequeue
		$a_01_2 = {52 00 73 00 6a 00 68 00 72 00 6b 00 62 00 67 00 74 00 6c 00 71 00 6c 00 75 00 61 00 6f 00 62 00 74 00 6f 00 71 00 61 00 68 00 69 00 72 00 } //01 00  Rsjhrkbgtlqluaobtoqahir
		$a_03_3 = {63 00 64 00 6e 00 2e 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 2f 00 61 00 74 00 74 00 61 00 63 00 68 00 6d 00 65 00 6e 00 74 00 73 00 2f 00 39 00 90 02 60 2e 00 6a 00 70 00 67 00 90 00 } //01 00 
		$a_01_4 = {52 65 76 65 72 73 65 } //00 00  Reverse
	condition:
		any of ($a_*)
 
}