
rule Trojan_Win32_Stelega_RB_MTB{
	meta:
		description = "Trojan:Win32/Stelega.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {88 4d ff 0f b6 55 ff 33 55 f8 88 55 ff 0f b6 45 ff 2b 45 f8 88 45 ff 0f b6 4d ff f7 d9 88 4d ff 0f b6 55 ff 33 55 f8 88 55 ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}