
rule Trojan_Win32_LoggerMachete_B{
	meta:
		description = "Trojan:Win32/LoggerMachete.B,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {65 4a 7a 56 50 47 6c 33 32 7a 69 53 33 2f 30 72 4e 50 54 7a 69 6f } //1 eJzVPGl32ziS3/0rNPTzio
		$a_01_1 = {70 79 32 65 78 65 5c 62 6f 6f 74 5f 63 6f 6d 6d 6f 6e 2e 70 79 74 } //1 py2exe\boot_common.pyt
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}