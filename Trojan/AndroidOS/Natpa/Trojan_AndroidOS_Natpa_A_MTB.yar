
rule Trojan_AndroidOS_Natpa_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Natpa.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2e 69 61 70 70 2e 6d 6d 61 70 70 } //1 com.iapp.mmapp
		$a_01_1 = {5a 59 46 5f 43 68 61 6e 6e 65 6c 49 44 2e 74 78 74 } //1 ZYF_ChannelID.txt
		$a_01_2 = {2f 64 6f 77 6e 5f 64 69 61 6c 6f 67 5f 69 6e 73 74 61 6c 6c 2e 70 6e 67 } //1 /down_dialog_install.png
		$a_01_3 = {61 70 6b 2e 62 6f 79 61 31 39 39 33 2e 63 6f 6d } //1 apk.boya1993.com
		$a_01_4 = {67 65 74 53 6d 73 43 65 6e 74 65 72 } //1 getSmsCenter
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}