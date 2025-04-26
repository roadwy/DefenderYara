
rule Trojan_Linux_Ddostf_A_MTB{
	meta:
		description = "Trojan:Linux/Ddostf.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {76 61 72 2f 72 75 6e 2f 6b 6c 73 73 2e 70 69 64 } //1 var/run/klss.pid
		$a_00_1 = {64 64 6f 73 2e 74 66 } //1 ddos.tf
		$a_00_2 = {2f 76 61 72 2f 74 6d 70 2f 74 65 73 74 2e 6c 6f 67 } //1 /var/tmp/test.log
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}