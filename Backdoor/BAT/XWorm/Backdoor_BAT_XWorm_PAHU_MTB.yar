
rule Backdoor_BAT_XWorm_PAHU_MTB{
	meta:
		description = "Backdoor:BAT/XWorm.PAHU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {13 19 11 11 11 18 91 13 1a 11 11 11 18 11 11 11 19 91 9c 11 11 11 19 11 1a 9c 11 16 11 17 11 10 11 17 91 11 11 11 11 11 18 91 11 11 11 19 91 58 20 ff 00 00 00 5f 91 61 d2 9c 11 17 } //2
		$a_00_1 = {76 00 62 00 6f 00 78 00 73 00 65 00 72 00 76 00 69 00 63 00 65 00 } //1 vboxservice
		$a_00_2 = {77 00 69 00 72 00 65 00 73 00 68 00 61 00 72 00 6b 00 } //1 wireshark
		$a_00_3 = {70 00 72 00 6f 00 63 00 6d 00 6f 00 6e 00 } //1 procmon
	condition:
		((#a_01_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=5
 
}