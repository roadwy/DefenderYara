
rule Trojan_AndroidOS_BanBara_A_MTB{
	meta:
		description = "Trojan:AndroidOS/BanBara.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2e 6f 72 63 68 65 73 74 72 61 2e 77 61 74 63 68 64 6f 67 2e 43 32 43 } //1 com.orchestra.watchdog.C2C
		$a_01_1 = {77 61 69 74 34 73 65 72 76 69 63 65 4d 65 73 73 65 6e 67 65 72 } //1 wait4serviceMessenger
		$a_00_2 = {35 14 12 00 34 25 03 00 12 05 48 06 09 04 48 07 0a 05 b7 76 8d 66 4f 06 09 04 d8 04 04 01 d8 05 05 01 28 ef } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}