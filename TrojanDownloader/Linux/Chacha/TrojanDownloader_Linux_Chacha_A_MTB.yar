
rule TrojanDownloader_Linux_Chacha_A_MTB{
	meta:
		description = "TrojanDownloader:Linux/Chacha.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_02_0 = {68 74 74 70 3a 2f 90 02 20 3a 38 38 35 32 2f 70 63 90 00 } //1
		$a_01_1 = {64 61 74 61 2f 6c 6f 63 61 6c 2f 74 6d 70 2f 74 6d 70 2e 6c 00 70 79 74 68 6f 6e 33 2e 4f } //2 慤慴氯捯污琯灭琯灭氮瀀瑹潨㍮伮
		$a_00_2 = {2f 65 74 63 2f 72 63 2e 64 2f 72 63 25 64 2e 64 2f 53 39 30 25 73 } //1 /etc/rc.d/rc%d.d/S90%s
		$a_00_3 = {2f 74 6d 70 2f 74 6d 70 6e 61 6d 5f 58 58 58 58 58 58 } //1 /tmp/tmpnam_XXXXXX
		$a_02_4 = {63 61 73 65 20 24 31 20 69 6e 90 02 03 73 74 61 72 74 29 90 02 05 25 73 90 02 05 90 02 05 73 74 6f 70 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_01_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_02_4  & 1)*1) >=4
 
}