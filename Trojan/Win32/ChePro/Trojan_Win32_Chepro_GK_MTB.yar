
rule Trojan_Win32_Chepro_GK_MTB{
	meta:
		description = "Trojan:Win32/Chepro.GK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 55 a4 2b d0 8b 45 d4 31 10 83 45 ec 04 83 45 d4 04 8b 45 ec 3b 45 d0 72 c3 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}