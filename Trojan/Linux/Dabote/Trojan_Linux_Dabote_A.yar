
rule Trojan_Linux_Dabote_A{
	meta:
		description = "Trojan:Linux/Dabote.A,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_00_0 = {64 79 6e 64 64 6e 73 2e 63 66 2f 73 74 61 72 74 2f 68 65 6c 70 2f 73 74 61 72 74 20 2d 4f 20 73 74 61 72 74 } //1 dynddns.cf/start/help/start -O start
		$a_00_1 = {63 68 6d 6f 64 20 37 37 37 20 2f 65 74 63 2f 69 6e 69 74 2e 64 2f 73 74 61 72 74 70 73 74 61 72 74 } //1 chmod 777 /etc/init.d/startpstart
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=1
 
}