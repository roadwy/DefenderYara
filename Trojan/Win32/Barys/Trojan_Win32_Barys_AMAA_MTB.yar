
rule Trojan_Win32_Barys_AMAA_MTB{
	meta:
		description = "Trojan:Win32/Barys.AMAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8d 48 1e 30 4c 05 d0 48 ff c0 48 83 f8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}