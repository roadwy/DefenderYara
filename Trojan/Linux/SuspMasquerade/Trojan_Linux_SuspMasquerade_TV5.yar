
rule Trojan_Linux_SuspMasquerade_TV5{
	meta:
		description = "Trojan:Linux/SuspMasquerade.TV5,SIGNATURE_TYPE_CMDHSTR_EXT,0b 00 0b 00 05 00 00 "
		
	strings :
		$a_00_0 = {63 00 75 00 72 00 6c 00 20 00 } //1 curl 
		$a_00_1 = {77 00 67 00 65 00 74 00 20 00 } //1 wget 
		$a_00_2 = {74 00 70 00 63 00 70 00 2e 00 74 00 61 00 72 00 2e 00 67 00 7a 00 } //1 tpcp.tar.gz
		$a_00_3 = {73 00 63 00 61 00 6e 00 2e 00 61 00 71 00 75 00 61 00 73 00 65 00 63 00 75 00 72 00 74 00 69 00 79 00 2e 00 6f 00 72 00 67 00 } //10 scan.aquasecurtiy.org
		$a_00_4 = {61 70 70 6c 69 63 61 74 69 6f 6e 2f 6a 73 6f 6e } //-100 application/json
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*10+(#a_00_4  & 1)*-100) >=11
 
}