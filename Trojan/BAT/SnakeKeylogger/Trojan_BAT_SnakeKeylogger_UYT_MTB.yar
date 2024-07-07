
rule Trojan_BAT_SnakeKeylogger_UYT_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.UYT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 0d 00 00 "
		
	strings :
		$a_81_0 = {43 6f 75 72 69 65 72 20 4e 65 77 } //1 Courier New
		$a_81_1 = {43 68 69 63 6b 65 6e 49 6e 76 61 64 65 72 73 } //1 ChickenInvaders
		$a_81_2 = {4c 49 4e 4b 53 5f 49 4e 5f 48 45 52 45 } //1 LINKS_IN_HERE
		$a_81_3 = {34 44 35 41 39 30 30 30 30 33 30 30 30 30 30 30 30 34 30 30 30 30 30 30 46 46 46 46 30 30 30 30 42 38 30 30 30 30 30 30 30 30 30 30 30 30 30 30 } //1 4D5A90000300000004000000FFFF0000B800000000000000
		$a_81_4 = {48 6f 73 74 45 78 65 63 75 74 69 6f 6e 43 6f 6e 74 65 78 74 } //1 HostExecutionContext
		$a_81_5 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_81_6 = {67 65 74 5f 4b 65 79 43 6f 64 65 } //1 get_KeyCode
		$a_81_7 = {4e 65 77 4c 61 74 65 42 69 6e 64 69 6e 67 } //1 NewLateBinding
		$a_81_8 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //1 MemoryStream
		$a_81_9 = {52 65 73 75 6d 65 4c 61 79 6f 75 74 } //1 ResumeLayout
		$a_81_10 = {54 68 72 65 61 64 53 74 61 72 74 } //1 ThreadStart
		$a_81_11 = {43 6f 6e 76 65 72 74 46 72 6f 6d 55 74 66 33 32 } //1 ConvertFromUtf32
		$a_81_12 = {53 74 72 69 6e 67 42 75 69 6c 64 65 72 } //1 StringBuilder
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1) >=13
 
}