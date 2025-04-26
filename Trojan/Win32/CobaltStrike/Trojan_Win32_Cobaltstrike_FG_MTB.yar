
rule Trojan_Win32_Cobaltstrike_FG_MTB{
	meta:
		description = "Trojan:Win32/Cobaltstrike.FG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 fc 33 d2 f7 75 0c 8b 45 08 0f be 14 10 33 ca 8b 45 10 03 45 fc 88 08 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}