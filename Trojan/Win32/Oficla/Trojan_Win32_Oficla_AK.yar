
rule Trojan_Win32_Oficla_AK{
	meta:
		description = "Trojan:Win32/Oficla.AK,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {66 74 70 3a 2f 2f 25 73 3a 25 73 40 25 73 } //1 ftp://%s:%s@%s
		$a_00_1 = {5c 73 6d 64 61 74 61 2e 64 61 74 } //1 \smdata.dat
		$a_02_2 = {0f be 00 83 f8 48 75 32 8b 90 01 05 0f be 40 03 83 f8 74 75 23 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}