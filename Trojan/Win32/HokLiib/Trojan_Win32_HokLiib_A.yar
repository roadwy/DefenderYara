
rule Trojan_Win32_HokLiib_A{
	meta:
		description = "Trojan:Win32/HokLiib.A,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {2d 00 44 00 6f 00 6e 00 74 00 53 00 74 00 6f 00 70 00 49 00 66 00 47 00 6f 00 69 00 6e 00 67 00 4f 00 6e 00 42 00 61 00 74 00 74 00 65 00 72 00 69 00 65 00 73 00 } //1 -DontStopIfGoingOnBatteries
		$a_00_1 = {2d 00 45 00 78 00 65 00 63 00 75 00 74 00 69 00 6f 00 6e 00 54 00 69 00 6d 00 65 00 4c 00 69 00 6d 00 69 00 74 00 20 00 27 00 30 00 30 00 3a 00 30 00 30 00 3a 00 30 00 30 00 27 00 } //1 -ExecutionTimeLimit '00:00:00'
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}