
rule Trojan_Win32_RemoteSysDisc_D_nslookup{
	meta:
		description = "Trojan:Win32/RemoteSysDisc.D!nslookup,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_00_0 = {6e 00 73 00 6c 00 6f 00 6f 00 6b 00 75 00 70 00 } //1 nslookup
		$a_00_1 = {6d 00 79 00 69 00 70 00 2e 00 6f 00 70 00 65 00 6e 00 64 00 6e 00 73 00 2e 00 63 00 6f 00 6d 00 } //-1 myip.opendns.com
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*-1) >=1
 
}