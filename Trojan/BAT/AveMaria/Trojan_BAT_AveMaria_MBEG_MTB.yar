
rule Trojan_BAT_AveMaria_MBEG_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.MBEG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {73 67 66 68 6a 66 66 66 66 64 72 66 68 64 64 66 68 66 66 66 61 6b 64 66 73 66 73 73 63 66 67 64 62 } //1 sgfhjffffdrfhddfhfffakdfsfsscfgdb
		$a_01_1 = {73 67 66 68 6a 66 66 66 67 64 72 66 68 64 64 68 66 66 66 61 64 66 73 66 73 73 63 66 67 64 62 } //1 sgfhjfffgdrfhddhfffadfsfsscfgdb
		$a_01_2 = {64 6a 66 66 6c 73 66 68 67 64 66 66 61 66 63 66 64 73 73 66 6b 66 68 67 6a } //1 djfflsfhgdffafcfdssfkfhgj
		$a_01_3 = {66 66 63 68 6b 66 66 6c 64 66 68 66 64 73 66 73 66 6a } //1 ffchkffldfhfdsfsfj
		$a_01_4 = {68 64 66 66 66 66 66 61 66 73 64 6b 66 73 68 } //1 hdfffffafsdkfsh
		$a_01_5 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } //1 RijndaelManaged
		$a_01_6 = {68 66 66 66 66 64 73 68 64 68 73 } //1 hffffdshdhs
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}