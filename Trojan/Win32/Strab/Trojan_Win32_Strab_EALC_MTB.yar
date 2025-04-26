
rule Trojan_Win32_Strab_EALC_MTB{
	meta:
		description = "Trojan:Win32/Strab.EALC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f af c0 0f b7 d7 03 ce 8a 54 55 ec 30 11 47 99 2b c2 d1 f8 46 3b f3 72 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}