
rule Trojan_Win32_Stealerc_GMG_MTB{
	meta:
		description = "Trojan:Win32/Stealerc.GMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b ca 66 c7 44 24 90 01 03 66 c7 44 24 90 01 03 8a 44 0c 58 34 ae 88 44 0c 60 41 83 f9 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}