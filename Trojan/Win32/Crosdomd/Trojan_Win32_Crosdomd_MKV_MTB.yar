
rule Trojan_Win32_Crosdomd_MKV_MTB{
	meta:
		description = "Trojan:Win32/Crosdomd.MKV!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_00_0 = {68 00 69 00 64 00 64 00 65 00 6e 00 } //1 hidden
		$a_00_1 = {62 00 79 00 70 00 61 00 73 00 73 00 } //1 bypass
		$a_00_2 = {54 00 65 00 6d 00 70 00 } //1 Temp
		$a_00_3 = {68 00 74 00 74 00 70 00 3a 00 } //2 http:
		$a_00_4 = {73 00 66 00 72 00 63 00 6c 00 61 00 6b 00 2e 00 63 00 6f 00 6d 00 } //5 sfrclak.com
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*2+(#a_00_4  & 1)*5) >=10
 
}