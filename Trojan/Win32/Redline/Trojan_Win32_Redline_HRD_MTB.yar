
rule Trojan_Win32_Redline_HRD_MTB{
	meta:
		description = "Trojan:Win32/Redline.HRD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {81 ad 54 fd ?? ?? ec f8 1e 4b 81 85 40 fe ?? ?? 7a 11 6e 08 81 85 c8 fe ?? ?? 25 62 73 2e 81 85 c8 fe ?? ?? 88 52 fd 38 81 ad 34 fd ?? ?? 25 7b f1 4d 81 ad 34 fd ?? ?? 4b 53 aa 49 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}