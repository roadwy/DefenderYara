
rule Trojan_Win32_VBInject_DS_MTB{
	meta:
		description = "Trojan:Win32/VBInject.DS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {ff 34 08 5b 66 0f 6e d3 [0-20] e8 [0-04] f6 [0-20] 66 0f 7e 14 08 [0-10] 83 e9 fc 81 f9 ?? ?? ?? ?? 75 ?? f6 [0-10] c3 f6 [0-10] 66 0f ef d1 c3 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}