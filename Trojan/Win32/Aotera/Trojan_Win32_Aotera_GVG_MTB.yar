
rule Trojan_Win32_Aotera_GVG_MTB{
	meta:
		description = "Trojan:Win32/Aotera.GVG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b c1 44 6b 45 a8 0d 41 03 c0 25 ff 0f 00 00 41 3b 47 08 73 44 4c 8b 45 90 45 8b d0 44 33 95 64 ff ff ff 45 88 54 07 10 ff c1 89 4d 8c 48 8b 8d } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}