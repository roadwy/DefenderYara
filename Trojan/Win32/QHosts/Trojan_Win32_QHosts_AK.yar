
rule Trojan_Win32_QHosts_AK{
	meta:
		description = "Trojan:Win32/QHosts.AK,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 65 23 74 23 63 5c 68 23 6f 23 73 23 74 73 } //01 00  \e#t#c\h#o#s#ts
		$a_01_1 = {22 44 69 23 73 23 61 62 23 6c 65 23 } //01 00  "Di#s#ab#le#
		$a_01_2 = {5c 68 73 74 2e 70 6e } //00 00  \hst.pn
	condition:
		any of ($a_*)
 
}