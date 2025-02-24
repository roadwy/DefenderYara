
rule Trojan_Win32_PersistenceViaScheduledTask_AB{
	meta:
		description = "Trojan:Win32/PersistenceViaScheduledTask.AB,SIGNATURE_TYPE_CMDHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_02_0 = {73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 2e 00 65 00 78 00 65 00 20 00 2f 00 43 00 72 00 65 00 61 00 74 00 65 00 20 00 2f 00 74 00 6e 00 [0-05] 61 00 74 00 74 00 61 00 63 00 6b 00 69 00 71 00 20 00 74 00 61 00 73 00 6b 00 } //3
		$a_02_1 = {2f 00 74 00 72 00 [0-05] 63 00 6d 00 64 00 20 00 2f 00 63 00 [0-40] 2e 00 62 00 61 00 74 00 [0-40] 2f 00 72 00 75 00 20 00 73 00 79 00 73 00 74 00 65 00 6d 00 } //3
	condition:
		((#a_02_0  & 1)*3+(#a_02_1  & 1)*3) >=6
 
}