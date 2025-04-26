
rule Trojan_Win32_Gepys_RPL_MTB{
	meta:
		description = "Trojan:Win32/Gepys.RPL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 45 ac 88 45 d6 0f b6 55 d7 89 f1 d3 ea 88 14 3b 8b 45 e0 0f b6 55 d6 31 f2 88 14 03 ff 45 ec 81 7d ec e8 07 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}