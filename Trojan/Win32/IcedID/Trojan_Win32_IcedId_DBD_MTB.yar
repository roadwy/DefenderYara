
rule Trojan_Win32_IcedId_DBD_MTB{
	meta:
		description = "Trojan:Win32/IcedId.DBD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {6a 00 6a 01 6a 00 6a 00 8d 45 ?? 50 ff 15 ?? ?? ?? ?? 85 c0 75 3f 6a 08 6a 01 6a 00 6a 00 8d 4d 90 1b 00 51 ff 15 90 1b 01 85 c0 } //1
		$a_81_1 = {34 35 37 38 36 37 75 6a 68 66 67 68 64 68 67 64 67 66 64 67 68 } //1 457867ujhfghdhgdgfdgh
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}