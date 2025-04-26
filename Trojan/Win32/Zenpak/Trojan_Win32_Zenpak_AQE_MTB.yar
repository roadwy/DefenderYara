
rule Trojan_Win32_Zenpak_AQE_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.AQE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 45 fe 88 45 fd 8a 45 fd 0f b6 c8 0f b6 55 ff 31 d1 88 cc } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}