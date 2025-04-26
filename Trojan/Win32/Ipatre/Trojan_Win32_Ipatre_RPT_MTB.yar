
rule Trojan_Win32_Ipatre_RPT_MTB{
	meta:
		description = "Trojan:Win32/Ipatre.RPT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {4e 52 8b 16 4f 8b 07 47 33 d0 46 ff 0c 24 8a c6 46 aa } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}