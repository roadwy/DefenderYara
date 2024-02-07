
rule Trojan_Linux_Loki_B{
	meta:
		description = "Trojan:Linux/Loki.B,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {6c 6f 6b 69 64 3a 20 73 65 72 76 65 72 20 69 73 20 63 75 72 72 65 6e 74 6c 79 20 61 74 20 63 61 70 61 63 69 74 79 } //02 00  lokid: server is currently at capacity
		$a_00_1 = {6c 6f 6b 69 64 3a 20 43 61 6e 6e 6f 74 20 61 64 64 20 6b 65 79 } //02 00  lokid: Cannot add key
		$a_00_2 = {6c 6f 6b 69 64 20 2d 70 20 28 69 7c 75 29 } //00 00  lokid -p (i|u)
	condition:
		any of ($a_*)
 
}