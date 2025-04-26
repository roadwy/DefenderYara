
rule Trojan_Win32_Injuke_AMAI_MTB{
	meta:
		description = "Trojan:Win32/Injuke.AMAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 3b 83 45 ec 04 6a 00 e8 [0-1e] 8b 45 ec 3b 45 dc 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}