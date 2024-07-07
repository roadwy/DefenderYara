
rule Trojan_Win32_Keylogger_DAL_MTB{
	meta:
		description = "Trojan:Win32/Keylogger.DAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {f7 02 84 dc 87 43 44 d1 11 89 06 00 a0 c9 11 00 49 67 0d 26 db 8c b9 05 4e 83 9c 6e df 77 1d 5b 0e 21 3d 90 02 04 68 10 a7 38 08 00 2b 33 71 b5 43 6c 61 73 90 00 } //2
		$a_01_1 = {35 3c ff 1c 6a 05 f4 00 1c 16 05 fc c8 f4 00 1c 1d 05 fc c8 f4 00 1c 24 05 fc c8 f4 00 1c 2b 05 fc c8 f5 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}