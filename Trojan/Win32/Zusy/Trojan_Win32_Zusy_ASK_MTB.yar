
rule Trojan_Win32_Zusy_ASK_MTB{
	meta:
		description = "Trojan:Win32/Zusy.ASK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {34 33 2e 31 33 36 2e 32 33 34 2e 31 34 30 3a 37 38 39 30 2f 43 6c 6f 75 64 31 35 30 2f 53 53 44 54 48 6f 6f 6b 5f 49 4f 5f 4c 69 6e 6b 2e 74 78 74 } //01 00  43.136.234.140:7890/Cloud150/SSDTHook_IO_Link.txt
		$a_01_1 = {41 51 41 51 41 51 2e 74 78 74 } //01 00  AQAQAQ.txt
		$a_01_2 = {6b 74 6b 74 2e 74 78 74 } //01 00  ktkt.txt
		$a_01_3 = {43 4d 44 20 2f 43 20 53 43 20 44 45 4c 45 54 45 } //00 00  CMD /C SC DELETE
	condition:
		any of ($a_*)
 
}