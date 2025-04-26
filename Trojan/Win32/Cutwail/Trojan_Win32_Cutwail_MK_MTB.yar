
rule Trojan_Win32_Cutwail_MK_MTB{
	meta:
		description = "Trojan:Win32/Cutwail.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 d0 8a 18 8b 45 ?? be ?? ?? ?? ?? 99 f7 fe 89 d0 03 45 ?? 8a 00 31 d8 88 01 ff 45 ?? 8b 55 ?? 8b 45 ?? 39 c2 0f 92 c0 84 c0 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}