
rule Trojan_Win32_Nanocore_BY_MTB{
	meta:
		description = "Trojan:Win32/Nanocore.BY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {ff ff 5e 8b 0c 1f 53 bb ?? ?? ?? ?? 81 fb 90 1b 00 0f 85 ?? ?? ff ff 5b 68 ?? ?? ?? ?? 68 90 1b 03 83 c4 08 16 17 eb 1a } //1
		$a_02_1 = {f7 ff ff 5b 4b [0-05] 8b 17 [0-05] 31 da [0-06] 39 ca 75 ?? [0-05] 6a ?? 6a 90 1b 05 83 c4 08 16 17 eb 1a } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}