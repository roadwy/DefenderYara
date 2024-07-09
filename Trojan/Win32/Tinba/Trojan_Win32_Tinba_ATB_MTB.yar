
rule Trojan_Win32_Tinba_ATB_MTB{
	meta:
		description = "Trojan:Win32/Tinba.ATB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 03 03 c7 45 ec b4 98 4b c0 02 02 03 03 02 03 03 02 02 03 03 02 02 03 c7 45 ec ?? ?? ?? ?? 03 02 ff 75 f8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}