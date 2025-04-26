
rule Trojan_Win32_Fareit_Chl_MTB{
	meta:
		description = "Trojan:Win32/Fareit.Chl!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {91 8d 83 91 01 00 00 a1 ?? ?? ?? ?? 8b 40 28 03 07 a3 ?? ?? ?? ?? 05 dd 03 00 00 29 c3 0f af ca 6a 00 6a 01 8b 07 50 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}