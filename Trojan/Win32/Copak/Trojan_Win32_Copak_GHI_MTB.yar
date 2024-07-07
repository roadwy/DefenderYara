
rule Trojan_Win32_Copak_GHI_MTB{
	meta:
		description = "Trojan:Win32/Copak.GHI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 0f 21 f6 4b 81 c7 90 01 04 89 db 81 c3 90 01 04 39 c7 75 90 01 01 42 81 eb 90 01 04 c3 89 d6 7f 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}