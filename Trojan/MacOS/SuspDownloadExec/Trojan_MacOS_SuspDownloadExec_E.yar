
rule Trojan_MacOS_SuspDownloadExec_E{
	meta:
		description = "Trojan:MacOS/SuspDownloadExec.E,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {74 00 6f 00 75 00 63 00 68 00 20 00 2f 00 70 00 72 00 69 00 76 00 61 00 74 00 65 00 2f 00 74 00 6d 00 70 00 } //1 touch /private/tmp
		$a_00_1 = {63 00 75 00 72 00 6c 00 20 00 } //1 curl 
		$a_00_2 = {2f 00 44 00 79 00 6c 00 64 00 44 00 65 00 4e 00 65 00 75 00 72 00 61 00 6c 00 79 00 7a 00 65 00 72 00 } //1 /DyldDeNeuralyzer
		$a_00_3 = {63 00 68 00 6d 00 6f 00 64 00 20 00 2b 00 78 00 20 00 2f 00 70 00 72 00 69 00 76 00 61 00 74 00 65 00 2f 00 74 00 6d 00 70 00 } //1 chmod +x /private/tmp
		$a_00_4 = {26 00 26 00 20 00 2f 00 70 00 72 00 69 00 76 00 61 00 74 00 65 00 2f 00 74 00 6d 00 70 00 2f 00 } //1 && /private/tmp/
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}