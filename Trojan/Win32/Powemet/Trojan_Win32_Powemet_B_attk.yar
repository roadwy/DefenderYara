
rule Trojan_Win32_Powemet_B_attk{
	meta:
		description = "Trojan:Win32/Powemet.B!attk,SIGNATURE_TYPE_CMDHSTR_EXT,10 00 10 00 04 00 00 "
		
	strings :
		$a_00_0 = {72 00 65 00 67 00 73 00 76 00 72 00 33 00 32 00 } //5 regsvr32
		$a_00_1 = {2f 00 69 00 3a 00 75 00 72 00 6c 00 3a 00 68 00 74 00 74 00 70 00 } //1 /i:url:http
		$a_00_2 = {2d 00 69 00 3a 00 75 00 72 00 6c 00 3a 00 68 00 74 00 74 00 70 00 } //1 -i:url:http
		$a_00_3 = {20 00 73 00 63 00 72 00 6f 00 62 00 6a 00 2e 00 64 00 6c 00 6c 00 } //10  scrobj.dll
	condition:
		((#a_00_0  & 1)*5+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*10) >=16
 
}