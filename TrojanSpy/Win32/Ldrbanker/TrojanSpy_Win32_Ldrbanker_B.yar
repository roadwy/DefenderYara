
rule TrojanSpy_Win32_Ldrbanker_B{
	meta:
		description = "TrojanSpy:Win32/Ldrbanker.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {43 00 3a 00 5c 00 63 00 6c 00 69 00 65 00 6e 00 74 00 70 00 63 00 5c 00 64 00 62 00 6c 00 6f 00 67 00 } //1 C:\clientpc\dblog
		$a_01_1 = {2f 00 64 00 62 00 6c 00 6f 00 67 00 } //1 /dblog
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}