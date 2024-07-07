
rule Trojan_Win32_Amadey_GHP_MTB{
	meta:
		description = "Trojan:Win32/Amadey.GHP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 00 6a 00 ff 15 90 01 04 8b 44 24 90 01 01 81 44 24 90 01 01 47 86 c8 61 33 c6 2b d8 83 6c 24 90 01 02 89 44 24 90 01 01 89 5c 24 90 01 01 0f 85 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}