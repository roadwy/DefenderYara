
rule Trojan_Win32_CosmicDuke_CCIE_MTB{
	meta:
		description = "Trojan:Win32/CosmicDuke.CCIE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {53 68 28 21 40 00 bf f4 20 40 00 57 ff 75 fc ff 15 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}