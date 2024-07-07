
rule Trojan_Win32_Gepys_DSC_MTB{
	meta:
		description = "Trojan:Win32/Gepys.DSC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {0f b6 5d fc 01 d8 88 01 eb 90 01 01 01 f8 88 06 8a 45 fc 0c 01 0f b6 f0 89 d8 99 f7 fe eb 90 00 } //1
		$a_00_1 = {89 d1 0f b6 00 8d 7b 01 99 f7 ff 88 45 fc 8a 01 0c 01 0f b6 f8 89 d8 99 f7 ff 0f b6 39 eb } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}