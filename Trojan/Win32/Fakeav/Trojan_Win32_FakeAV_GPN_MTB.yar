
rule Trojan_Win32_FakeAV_GPN_MTB{
	meta:
		description = "Trojan:Win32/FakeAV.GPN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 81 ec 80 04 00 00 53 56 57 89 95 80 fb ff ff 89 8d 84 fb ff ff c7 45 fc } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}