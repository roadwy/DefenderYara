
rule Trojan_Win32_Lumma_RZ_MTB{
	meta:
		description = "Trojan:Win32/Lumma.RZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {04 4e 34 70 2c 65 34 22 2c 73 } //1 丄瀴攬∴猬
	condition:
		((#a_01_0  & 1)*1) >=1
 
}