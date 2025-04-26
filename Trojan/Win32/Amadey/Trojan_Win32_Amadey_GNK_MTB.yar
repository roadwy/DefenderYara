
rule Trojan_Win32_Amadey_GNK_MTB{
	meta:
		description = "Trojan:Win32/Amadey.GNK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 45 fc 50 e8 ?? ?? ?? ?? 8b 45 08 03 c6 59 8a 4d fc 30 08 46 3b 75 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}