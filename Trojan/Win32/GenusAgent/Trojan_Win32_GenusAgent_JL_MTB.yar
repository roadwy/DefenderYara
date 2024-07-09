
rule Trojan_Win32_GenusAgent_JL_MTB{
	meta:
		description = "Trojan:Win32/GenusAgent.JL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {68 10 27 00 00 ff 15 00 c0 ?? ?? 33 c0 c2 10 00 3b 0d } //1
		$a_01_1 = {a8 00 00 00 7e 00 00 00 00 00 00 5f 12 00 00 00 10 00 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}