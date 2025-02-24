
rule Trojan_Win32_Symmi_GTZ_MTB{
	meta:
		description = "Trojan:Win32/Symmi.GTZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {2e 33 2e 37 2e 30 00 9c 66 51 8d 64 24 } //5
		$a_03_1 = {54 33 ce 67 f7 83 ?? ?? ?? ?? ?? ?? 09 0f 31 8b ?? ?? ?? ?? 8f 44 24 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}