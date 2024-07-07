
rule Trojan_Win32_Cutwail_MK_MTB{
	meta:
		description = "Trojan:Win32/Cutwail.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 d0 8a 18 8b 45 90 01 01 be 90 01 04 99 f7 fe 89 d0 03 45 90 01 01 8a 00 31 d8 88 01 ff 45 90 01 01 8b 55 90 01 01 8b 45 90 01 01 39 c2 0f 92 c0 84 c0 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}