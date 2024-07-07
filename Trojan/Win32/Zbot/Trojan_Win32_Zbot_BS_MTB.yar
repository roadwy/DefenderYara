
rule Trojan_Win32_Zbot_BS_MTB{
	meta:
		description = "Trojan:Win32/Zbot.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {67 34 31 30 38 ce bb 90 02 04 3e f7 97 a1 e3 e4 80 7a 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}