
rule Backdoor_Linux_Gafgyt_cg_MTB{
	meta:
		description = "Backdoor:Linux/Gafgyt.cg!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {3f 3f 68 3f 74 3f 74 3f 70 3f 3f 68 3f 65 3f 78 3f 3f 3f 3f 68 3f 74 3f 74 3f 70 3f 3f 68 3f 65 3f 78 3f 3f 3f 3f 68 3f 74 3f 74 3f 70 3f 3f 68 3f 65 3f 78 3f 3f 3f 3f 68 3f 74 3f 74 3f 70 3f 3f 66 3f 6c 3f 6f 3f 6f 3f 64 3f 3f 3f 3f 68 3f 74 3f 74 3f 70 3f 3f 66 3f 6c 3f 6f 3f 6f 3f 64 3f 3f 3f 3f 68 3f 74 3f 74 3f 70 3f 3f 66 3f 6c 3f 6f 3f 6f 3f 64 3f 3f } //01 00  ??h?t?t?p??h?e?x????h?t?t?p??h?e?x????h?t?t?p??h?e?x????h?t?t?p??f?l?o?o?d????h?t?t?p??f?l?o?o?d????h?t?t?p??f?l?o?o?d??
		$a_00_1 = {3f 3f 68 3f 74 3f 74 3f 70 3f 72 3f 61 3f 6e 3f 64 3f 3f 3f 3f 68 3f 74 3f 74 3f 70 3f 72 3f 61 3f 6e 3f 64 3f 3f 3f 3f 68 3f 74 3f 74 3f 70 3f 72 3f 61 3f 6e 3f 64 3f 3f 3f 3f 68 3f 74 3f 74 3f 70 3f 3f 66 3f 6c 3f 6f 3f 6f 3f 64 3f 3f 3f 3f 68 3f 74 3f 74 3f 70 3f 3f 66 3f 6c 3f 6f 3f 6f 3f 64 3f 3f 3f 3f 68 3f 74 3f 74 3f 70 3f 3f 66 3f 6c 3f 6f 3f 6f 3f 64 3f 3f } //01 00  ??h?t?t?p?r?a?n?d????h?t?t?p?r?a?n?d????h?t?t?p?r?a?n?d????h?t?t?p??f?l?o?o?d????h?t?t?p??f?l?o?o?d????h?t?t?p??f?l?o?o?d??
		$a_00_2 = {76 73 65 61 74 74 61 63 6b } //01 00  vseattack
		$a_00_3 = {53 65 6e 64 53 54 44 48 45 58 } //00 00  SendSTDHEX
	condition:
		any of ($a_*)
 
}