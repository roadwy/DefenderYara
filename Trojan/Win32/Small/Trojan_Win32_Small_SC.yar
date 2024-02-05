
rule Trojan_Win32_Small_SC{
	meta:
		description = "Trojan:Win32/Small.SC,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 03 00 00 0a 00 "
		
	strings :
		$a_02_0 = {8b 1c 24 80 3b 43 74 0a 6a 32 59 b0 90 01 01 30 03 43 e2 fb 66 33 db ff 93 00 20 00 00 33 c0 40 c9 c2 0c 00 90 00 } //0a 00 
		$a_02_1 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 43 6f 6d 6d 6f 6e 20 46 69 6c 65 73 5c 53 79 73 74 65 6d 5c 4d 53 90 02 08 2e 44 4c 4c 90 00 } //0a 00 
		$a_00_2 = {57 69 6e 45 78 65 63 } //00 00 
	condition:
		any of ($a_*)
 
}