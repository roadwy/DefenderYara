
rule Trojan_MacOS_OpinionSpy_A_MTB{
	meta:
		description = "Trojan:MacOS/OpinionSpy.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {25 6f 73 73 62 72 61 6e 64 72 6f 6f 74 25 } //01 00  %ossbrandroot%
		$a_00_1 = {70 6f 73 74 2e 73 65 63 75 72 65 73 74 75 64 69 65 73 2e 63 6f 6d 3a 34 34 33 2f 70 72 65 63 61 6d 70 61 69 67 6e 63 68 65 63 6b 2e 61 73 70 78 } //01 00  post.securestudies.com:443/precampaigncheck.aspx
		$a_00_2 = {43 61 6d 70 61 69 67 6e 5f 43 68 65 63 6b 5f 55 72 6c } //01 00  Campaign_Check_Url
		$a_00_3 = {2f 70 72 69 76 61 74 65 2f 74 6d 70 2f 69 6e 73 74 61 6c 6c 74 6d 70 2f } //00 00  /private/tmp/installtmp/
		$a_00_4 = {5d 04 00 } //00 66 
	condition:
		any of ($a_*)
 
}