
rule Trojan_MacOS_LightSpy_A_MTB{
	meta:
		description = "Trojan:MacOS/LightSpy.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2f 55 73 65 72 73 2f 61 69 72 2f 77 6f 72 6b 2f 46 5f 57 61 72 65 68 6f 75 73 65 2f 6d 61 63 2f 6e 65 77 5f 70 6c 75 67 69 6e 73 2f } //1 /Users/air/work/F_Warehouse/mac/new_plugins/
		$a_01_1 = {73 65 6e 64 4c 6f 67 57 69 74 68 43 6d 64 } //1 sendLogWithCmd
		$a_01_2 = {73 74 6f 70 45 78 65 63 43 6d 64 } //1 stopExecCmd
		$a_01_3 = {67 65 74 43 6d 64 54 79 70 65 57 69 74 68 43 6d 64 } //1 getCmdTypeWithCmd
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}