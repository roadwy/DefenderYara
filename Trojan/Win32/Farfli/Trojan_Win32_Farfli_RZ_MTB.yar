
rule Trojan_Win32_Farfli_RZ_MTB{
	meta:
		description = "Trojan:Win32/Farfli.RZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 5d e9 00 00 00 00 55 8b ec 53 56 57 83 cf ff e8 37 74 ed ff 8b f0 e8 ec 87 ed ff ff 75 14 8b 58 04 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}