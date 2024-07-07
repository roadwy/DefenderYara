
rule Trojan_Win32_Copak_GAF_MTB{
	meta:
		description = "Trojan:Win32/Copak.GAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {21 df 31 08 09 df 09 ff 81 c0 90 01 04 81 c3 90 01 04 81 c3 90 01 04 39 d0 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}