
rule Trojan_Win32_DanaBot_GF_MTB{
	meta:
		description = "Trojan:Win32/DanaBot.GF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 4d fc 30 04 31 b8 ?? ?? ?? ?? 83 f0 ?? 83 6d [0-10] 83 7d [0-10] 0f 8d } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}