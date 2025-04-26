
rule Trojan_Win32_Mediyes_AZNA_MTB{
	meta:
		description = "Trojan:Win32/Mediyes.AZNA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 08 8b 4d 10 8a 0c 0a 03 c6 30 08 8d 42 01 29 d2 f7 75 14 46 3b 75 0c 75 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}