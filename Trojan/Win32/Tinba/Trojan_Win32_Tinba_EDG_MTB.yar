
rule Trojan_Win32_Tinba_EDG_MTB{
	meta:
		description = "Trojan:Win32/Tinba.EDG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 c0 2b 44 24 10 03 c1 89 44 24 24 8b 44 24 40 0f af 44 24 2c 8d 44 10 0a 89 44 24 14 a1 ?? ?? ?? ?? 3b 05 } //5
	condition:
		((#a_02_0  & 1)*5) >=5
 
}