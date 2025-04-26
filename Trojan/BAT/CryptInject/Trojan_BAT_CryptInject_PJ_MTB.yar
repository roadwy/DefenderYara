
rule Trojan_BAT_CryptInject_PJ_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.PJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {73 73 73 73 73 73 73 73 73 73 64 73 73 73 73 73 73 73 73 2e 4d 79 } //1 ssssssssssdssssssss.My
		$a_81_1 = {64 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 2e 64 6c 6c } //1 dffffffffffffffffffff.dll
		$a_81_2 = {64 64 64 64 64 2e 64 6c 6c } //1 ddddd.dll
		$a_81_3 = {66 66 66 66 66 66 66 66 2e 64 6c 6c } //1 ffffffff.dll
		$a_81_4 = {64 66 64 64 64 64 64 64 64 66 66 2e 64 6c 6c } //1 dfdddddddff.dll
		$a_81_5 = {73 73 73 73 73 73 73 73 73 73 64 73 73 73 73 73 73 73 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 ssssssssssdssssssss.Resources.resources
		$a_81_6 = {24 24 6d 65 74 68 6f 64 30 78 36 30 30 30 30 30 37 2d 31 } //1 $$method0x6000007-1
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}