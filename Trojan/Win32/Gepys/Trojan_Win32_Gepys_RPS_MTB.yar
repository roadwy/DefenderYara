
rule Trojan_Win32_Gepys_RPS_MTB{
	meta:
		description = "Trojan:Win32/Gepys.RPS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {80 c9 01 f7 e1 89 45 b0 8b 45 bc 8b 55 b0 29 d0 8b 55 b4 88 04 13 ff 45 ec } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}