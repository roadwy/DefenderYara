
rule Trojan_Win32_Powemet_A_attk{
	meta:
		description = "Trojan:Win32/Powemet.A!attk,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {72 00 65 00 67 00 73 00 76 00 72 00 33 00 32 00 [0-f0] 2f 00 69 00 3a 00 68 00 74 00 74 00 70 00 } //1
		$a_02_1 = {72 00 65 00 67 00 73 00 76 00 72 00 33 00 32 00 [0-f0] 2d 00 69 00 3a 00 68 00 74 00 74 00 70 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}
rule Trojan_Win32_Powemet_A_attk_2{
	meta:
		description = "Trojan:Win32/Powemet.A!attk,SIGNATURE_TYPE_CMDHSTR_EXT,10 00 10 00 04 00 00 "
		
	strings :
		$a_00_0 = {72 00 65 00 67 00 73 00 76 00 72 00 33 00 32 00 } //5 regsvr32
		$a_00_1 = {2f 00 69 00 3a 00 68 00 74 00 74 00 70 00 } //1 /i:http
		$a_00_2 = {2d 00 69 00 3a 00 68 00 74 00 74 00 70 00 } //1 -i:http
		$a_00_3 = {20 00 73 00 63 00 72 00 6f 00 62 00 6a 00 2e 00 64 00 6c 00 6c 00 } //10  scrobj.dll
	condition:
		((#a_00_0  & 1)*5+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*10) >=16
 
}
rule Trojan_Win32_Powemet_A_attk_3{
	meta:
		description = "Trojan:Win32/Powemet.A!attk,SIGNATURE_TYPE_CMDHSTR_EXT,15 00 15 00 06 00 00 "
		
	strings :
		$a_00_0 = {72 00 65 00 67 00 73 00 76 00 72 00 33 00 32 00 } //5 regsvr32
		$a_00_1 = {2f 00 73 00 } //5 /s
		$a_00_2 = {2f 00 75 00 } //5 /u
		$a_00_3 = {2f 00 69 00 3a 00 68 00 74 00 74 00 70 00 } //1 /i:http
		$a_00_4 = {2f 00 69 00 3a 00 5c 00 5c 00 } //1 /i:\\
		$a_00_5 = {73 00 63 00 72 00 6f 00 62 00 6a 00 2e 00 64 00 6c 00 6c 00 } //5 scrobj.dll
	condition:
		((#a_00_0  & 1)*5+(#a_00_1  & 1)*5+(#a_00_2  & 1)*5+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*5) >=21
 
}