
rule Trojan_Win32_Androm_RJ_MTB{
	meta:
		description = "Trojan:Win32/Androm.RJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 c0 83 c8 60 03 c7 03 c0 42 8b f8 8a 02 84 c0 75 ed } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}