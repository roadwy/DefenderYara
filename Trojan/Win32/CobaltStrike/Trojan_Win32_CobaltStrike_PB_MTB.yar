
rule Trojan_Win32_CobaltStrike_PB_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 85 48 f8 ff ff 83 ec 18 c7 44 24 0c 00 00 00 00 c7 44 24 08 00 00 00 00 c7 44 24 04 00 00 00 00 c7 04 24 00 00 00 00 ff d0 } //1
		$a_01_1 = {6d 69 6e 69 6d 61 61 63 63 75 73 61 6d 75 73 6e 69 68 69 6c 76 6f 6c 75 70 74 61 73 65 74 39 30 2e 64 6c 6c } //1 minimaaccusamusnihilvoluptaset90.dll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}