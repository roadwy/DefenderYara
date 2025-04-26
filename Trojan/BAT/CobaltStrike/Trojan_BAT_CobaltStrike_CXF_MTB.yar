
rule Trojan_BAT_CobaltStrike_CXF_MTB{
	meta:
		description = "Trojan:BAT/CobaltStrike.CXF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {61 00 70 00 69 00 2e 00 67 00 6f 00 67 00 6c 00 65 00 61 00 70 00 69 00 2e 00 63 00 6c 00 69 00 63 00 6b 00 2f 00 66 00 69 00 6c 00 65 00 2f 00 53 00 79 00 73 00 74 00 65 00 6d } //1
		$a_01_1 = {61 70 69 2e 67 6f 67 6c 65 61 70 69 2e 63 6c 69 63 6b 2f 66 69 6c 65 2f 53 79 73 74 65 6d 2f } //1 api.gogleapi.click/file/System/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}