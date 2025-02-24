
rule Trojan_Win32_Tepfer_SPCI_MTB{
	meta:
		description = "Trojan:Win32/Tepfer.SPCI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {c1 e8 05 89 45 fc 8b 45 f8 8b 55 e8 01 55 fc 03 c7 33 f0 81 3d } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}