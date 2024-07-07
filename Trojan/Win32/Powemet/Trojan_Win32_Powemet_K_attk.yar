
rule Trojan_Win32_Powemet_K_attk{
	meta:
		description = "Trojan:Win32/Powemet.K!attk,SIGNATURE_TYPE_CMDHSTR_EXT,64 00 0b 00 04 00 00 "
		
	strings :
		$a_00_0 = {2e 00 64 00 6c 00 6c 00 } //65436 .dll
		$a_00_1 = {72 00 65 00 67 00 73 00 76 00 72 00 33 00 32 00 } //10 regsvr32
		$a_00_2 = {2e 00 6a 00 70 00 67 00 } //1 .jpg
		$a_00_3 = {2e 00 63 00 73 00 76 00 } //1 .csv
	condition:
		((#a_00_0  & 1)*65436+(#a_00_1  & 1)*10+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=11
 
}