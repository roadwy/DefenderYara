
rule Trojan_Win32_DanaBot_GK_MTB{
	meta:
		description = "Trojan:Win32/DanaBot.GK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {30 04 3e 56 [0-25] 83 c4 ?? 8b f0 3b f3 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}