
rule Trojan_Win64_CobaltStrike_NWO_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.NWO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {80 b4 05 b0 fc ff ff 1a 40 3d } //1
		$a_01_1 = {53 74 61 72 74 55 73 65 72 4d 6f 64 65 42 72 6f 77 73 65 72 49 6e 6a 65 63 74 69 6f 6e } //1 StartUserModeBrowserInjection
		$a_01_2 = {53 74 6f 70 55 73 65 72 4d 6f 64 65 42 72 6f 77 73 65 72 49 6e 6a 65 63 74 69 6f 6e } //1 StopUserModeBrowserInjection
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}