
rule Trojan_MacOS_OpinionSpy_C_MTB{
	meta:
		description = "Trojan:MacOS/OpinionSpy.C!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {73 65 63 75 72 65 73 74 75 64 69 65 73 2e 63 6f 6d } //1 securestudies.com
		$a_00_1 = {72 75 6c 65 53 65 63 72 65 63 74 4b 65 79 } //1 ruleSecrectKey
		$a_00_2 = {25 6f 73 73 62 72 61 6e 64 72 6f 6f 74 25 } //1 %ossbrandroot%
		$a_00_3 = {4d 61 63 6d 65 74 65 72 20 6c 6f 61 64 20 63 6d 64 } //1 Macmeter load cmd
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}