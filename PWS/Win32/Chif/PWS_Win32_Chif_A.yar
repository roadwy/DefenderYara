
rule PWS_Win32_Chif_A{
	meta:
		description = "PWS:Win32/Chif.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 73 65 72 00 50 61 73 73 00 66 74 70 3a 2f 2f 00 3a 00 40 00 63 68 69 67 00 41 63 63 65 70 74 3a 20 2a 2f 2a 00 } //01 00  獕牥倀獡s瑦㩰⼯㨀䀀挀楨g捁散瑰›⼪*
		$a_01_1 = {81 3b 50 61 73 73 75 ee 83 c3 04 8d bd b8 fd ff ff 43 66 81 3b 3c 2f 74 0a 8a 03 88 07 47 c6 07 00 eb ee } //00 00 
	condition:
		any of ($a_*)
 
}