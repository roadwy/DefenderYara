
rule Ransom_Win32_Hive_SE{
	meta:
		description = "Ransom:Win32/Hive.SE,SIGNATURE_TYPE_CMDHSTR_EXT,6a 00 6a 00 0c 00 00 "
		
	strings :
		$a_00_0 = {20 00 2d 00 64 00 61 00 20 00 } //1  -da 
		$a_00_1 = {20 00 2d 00 6d 00 69 00 6e 00 2d 00 73 00 69 00 7a 00 65 00 20 00 } //1  -min-size 
		$a_00_2 = {20 00 2d 00 65 00 78 00 70 00 6c 00 69 00 63 00 69 00 74 00 2d 00 6f 00 6e 00 6c 00 79 00 20 00 } //1  -explicit-only 
		$a_00_3 = {20 00 2d 00 6e 00 65 00 74 00 77 00 6f 00 72 00 6b 00 2d 00 6f 00 6e 00 6c 00 79 00 20 00 } //1  -network-only 
		$a_00_4 = {20 00 2d 00 6c 00 6f 00 63 00 61 00 6c 00 2d 00 6f 00 6e 00 6c 00 79 00 20 00 } //1  -local-only 
		$a_00_5 = {20 00 2d 00 6e 00 6f 00 2d 00 64 00 69 00 73 00 63 00 6f 00 76 00 65 00 72 00 79 00 20 00 } //1  -no-discovery 
		$a_00_6 = {20 00 2d 00 6e 00 6f 00 2d 00 6d 00 6f 00 75 00 6e 00 74 00 65 00 64 00 20 00 } //1  -no-mounted 
		$a_00_7 = {20 00 2d 00 6e 00 6f 00 2d 00 6c 00 6f 00 63 00 61 00 6c 00 20 00 } //1  -no-local 
		$a_00_8 = {20 00 2d 00 77 00 6d 00 69 00 20 00 } //1  -wmi 
		$a_00_9 = {72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 } //5 rundll32
		$a_00_10 = {63 00 6d 00 64 00 } //5 cmd
		$a_00_11 = {20 00 2d 00 75 00 20 00 } //100  -u 
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*5+(#a_00_10  & 1)*5+(#a_00_11  & 1)*100) >=106
 
}