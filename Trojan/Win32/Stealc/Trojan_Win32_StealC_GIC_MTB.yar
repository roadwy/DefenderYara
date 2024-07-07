
rule Trojan_Win32_StealC_GIC_MTB{
	meta:
		description = "Trojan:Win32/StealC.GIC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {23 c1 66 89 85 90 01 04 0f be 55 ff 0f be 45 fe 33 d0 88 15 90 01 04 8b 8d 90 01 04 0f be 11 0f be 45 fd 0b d0 88 55 fe 8b 8d 90 01 04 0f be 11 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}