
rule Trojan_Win32_Fareit_IT_MTB{
	meta:
		description = "Trojan:Win32/Fareit.IT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {31 c9 31 d2 [0-30] 80 34 01 ?? ff 45 fc 41 89 d7 39 f9 ?? ?? 05 ?? ?? ?? ?? ff e0 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}