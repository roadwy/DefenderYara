
rule Trojan_Win32_Doina_MA_MTB{
	meta:
		description = "Trojan:Win32/Doina.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 f8 8b 4d 10 8a 09 88 08 8b 45 f8 40 89 45 f8 8b 45 10 40 89 45 10 8b 45 0c 48 89 45 0c eb } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}