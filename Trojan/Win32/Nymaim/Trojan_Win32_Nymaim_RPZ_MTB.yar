
rule Trojan_Win32_Nymaim_RPZ_MTB{
	meta:
		description = "Trojan:Win32/Nymaim.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c6 45 f8 6e c6 45 f9 74 c6 45 fa 64 c6 45 fb 6c c6 45 fc 6c c6 45 fd 00 c6 45 ec 61 c6 45 ed 64 c6 45 ee 76 c6 45 ef 61 c6 45 f0 70 c6 45 f1 69 c6 45 f2 33 c6 45 f3 32 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}