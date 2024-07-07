
rule Trojan_Win32_Nanocore_AKN_MTB{
	meta:
		description = "Trojan:Win32/Nanocore.AKN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff d0 eb 08 90 02 1f 81 7d 90 01 05 75 90 01 01 68 90 01 04 68 90 01 04 68 90 01 04 68 90 1b 03 ff 90 02 ef 68 90 01 04 68 90 01 04 68 90 01 04 68 90 1b 08 90 02 ff 31 fb 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}