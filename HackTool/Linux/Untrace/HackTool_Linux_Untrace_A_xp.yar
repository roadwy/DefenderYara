
rule HackTool_Linux_Untrace_A_xp{
	meta:
		description = "HackTool:Linux/Untrace.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2f 76 61 72 2f 6c 6f 67 2f 77 74 6d 70 } //1 /var/log/wtmp
		$a_01_1 = {2f 76 61 72 2f 72 75 6e 2f 75 74 6d 70 } //1 /var/run/utmp
		$a_01_2 = {72 65 63 6f 72 64 73 20 66 72 6f 6d 20 75 74 6d 70 2f 77 74 6d 70 } //1 records from utmp/wtmp
		$a_01_3 = {55 6e 74 72 61 63 65 20 62 79 20 53 65 43 54 6f 52 2d 58 } //1 Untrace by SeCToR-X
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}