
rule Trojan_Win32_Guloader_KV_MSR{
	meta:
		description = "Trojan:Win32/Guloader.KV!MSR,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {6b 6f 6f 6e 74 69 20 6c 6f 67 66 69 6c 65 72 6e 65 73 } //1 koonti logfilernes
		$a_81_1 = {61 7a 69 6d 69 6e 6f 62 65 6e 7a 65 6e 65 20 73 65 6c 76 70 6c 61 67 65 72 69 73 6b } //1 aziminobenzene selvplagerisk
		$a_81_2 = {61 63 69 64 69 73 65 20 62 65 71 75 65 61 74 68 73 } //1 acidise bequeaths
		$a_81_3 = {70 61 63 69 66 69 63 20 73 68 6f 61 6c 77 69 73 65 20 6c 69 6d 61 69 6c } //1 pacific shoalwise limail
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}