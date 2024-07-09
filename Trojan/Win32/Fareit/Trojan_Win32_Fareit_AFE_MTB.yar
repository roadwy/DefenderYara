
rule Trojan_Win32_Fareit_AFE_MTB{
	meta:
		description = "Trojan:Win32/Fareit.AFE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {56 33 f6 57 56 ff 15 ?? ?? ?? ?? 56 56 56 56 ff 15 ?? ?? ?? ?? 56 56 56 56 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}